// CRYPTIC Agent Runtime — read-only GitHub repository ingestion adapter.
// Requires a fine-grained GitHub token with Contents: Read-only on explicitly allowed repositories.
// Never crawls or ingests a repository until an operator configures an allowlist and calls a tool.

import { createHash } from "node:crypto";
import path from "node:path";
import { ingestText } from "./ingestion.mjs";

const allowedExtensions = new Set([
  ".md", ".txt", ".json", ".yaml", ".yml", ".toml",
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".sh", ".ps1", ".html", ".css", ".sql"
]);
const blockedSegments = new Set([
  ".git", "node_modules", ".venv", "venv", ".next", "dist",
  "secrets", "credentials", "private", "vendor"
]);
const blockedNames = /(^\.env($|\.)|(^|\.)id_rsa$|\.pem$|\.p12$|\.pfx$|\.key$|secret|credential|token|password)/i;
const maxFileBytes = Number(process.env.CRYPTIC_GITHUB_MAX_FILE_BYTES || 1048576);
const maxFiles = Number(process.env.CRYPTIC_GITHUB_MANIFEST_MAX_FILES || 2000);

function config() {
  const token = process.env.CRYPTIC_GITHUB_TOKEN || "";
  const allowed = (process.env.CRYPTIC_GITHUB_ALLOWED_REPOS || "")
    .split(",").map(value => value.trim().toLowerCase()).filter(Boolean);
  if (!token) throw new Error("CRYPTIC_GITHUB_TOKEN is not configured");
  if (!allowed.length) throw new Error("CRYPTIC_GITHUB_ALLOWED_REPOS is empty; GitHub access is fail-closed");
  return { token, allowed };
}

function validateRepo(repo) {
  if (typeof repo !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
    throw new Error("repo must be an owner/name pair");
  }
  const { allowed } = config();
  if (!allowed.includes(repo.toLowerCase())) throw new Error(`Repository is not allowlisted: ${repo}`);
  return repo;
}

function validatePath(filePath) {
  if (typeof filePath !== "string" || !filePath || filePath.startsWith("/") || filePath.includes("\\")) {
    throw new Error("path must be a repository-relative POSIX path");
  }
  const normalized = path.posix.normalize(filePath);
  if (normalized === "." || normalized.startsWith("../") || normalized !== filePath) {
    throw new Error("path traversal or non-canonical path rejected");
  }
  const segments = normalized.split("/");
  if (segments.some(segment => blockedSegments.has(segment.toLowerCase()) || blockedNames.test(segment))) {
    throw new Error("path is excluded by the GitHub ingestion safety policy");
  }
  const extension = path.posix.extname(normalized).toLowerCase();
  if (!allowedExtensions.has(extension)) throw new Error(`file extension is not ingestible: ${extension || "(none)"}`);
  return normalized;
}

async function githubRequest(url, accept = "application/vnd.github+json") {
  const { token } = config();
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: accept,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "CRYPTIC-Golem-Ingestion/0.1"
    },
    signal: AbortSignal.timeout(30000)
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`GitHub API request failed (${response.status}): ${detail.slice(0, 500)}`);
  }
  return response;
}

export async function githubRepositoryManifest({ repo, ref = "main" }) {
  repo = validateRepo(repo);
  if (typeof ref !== "string" || !ref.trim() || ref.length > 200) throw new Error("ref is invalid");
  const commitResponse = await githubRequest(`https://api.github.com/repos/${repo}/commits/${encodeURIComponent(ref)}`);
  const commit = await commitResponse.json();
  const treeSha = commit.commit?.tree?.sha;
  if (!treeSha) throw new Error("GitHub commit response did not include a tree SHA");
  const response = await githubRequest(`https://api.github.com/repos/${repo}/git/trees/${treeSha}?recursive=1`);
  const tree = await response.json();
  const entries = [];
  const skipped = { excluded_path: 0, unsupported_type: 0, unsupported_extension: 0, oversized: 0 };
  for (const item of tree.tree || []) {
    if (item.type !== "blob") { if (item.type !== "tree") skipped.unsupported_type++; continue; }
    const parts = item.path.split("/");
    if (parts.some(part => blockedSegments.has(part.toLowerCase()) || blockedNames.test(part))) {
      skipped.excluded_path++;
      continue;
    }
    const extension = path.posix.extname(item.path).toLowerCase();
    if (!allowedExtensions.has(extension)) { skipped.unsupported_extension++; continue; }
    if (Number(item.size || 0) > maxFileBytes) { skipped.oversized++; continue; }
    entries.push({ path: item.path, bytes: item.size || 0, git_blob_sha: item.sha, extension });
    if (entries.length >= maxFiles) break;
  }
  entries.sort((a, b) => a.path.localeCompare(b.path));
  const canonical = JSON.stringify({ repo, ref, commit_sha: commit.sha, tree_sha: tree.sha, entries });
  return {
    schema: "cryptic.github-repository-manifest.v1",
    repo,
    ref,
    tree_sha: tree.sha,
    manifest_sha256: createHash("sha256").update(canonical).digest("hex"),
    file_count: entries.length,
    truncated: Boolean(tree.truncated) || entries.length >= maxFiles,
    skipped,
    preview: entries.slice(0, 50),
    entries
  };
}

export async function ingestGithubFile({ repo, ref = "main", filePath, expectedBlobSha }) {
  repo = validateRepo(repo);
  const safePath = validatePath(filePath);
  if (typeof ref !== "string" || !ref.trim() || ref.length > 200) throw new Error("ref is invalid");
  if (typeof expectedBlobSha !== "string" || !/^[a-f0-9]{40}$/i.test(expectedBlobSha)) {
    throw new Error("expected_blob_sha from github_repository_manifest is required");
  }

  // Fetch by immutable Git blob SHA, not by a moving branch path.
  const url = `https://api.github.com/repos/${repo}/git/blobs/${expectedBlobSha}`;
  const response = await githubRequest(url);
  const blob = await response.json();
  if (blob.encoding !== "base64" || typeof blob.content !== "string") {
    throw new Error("GitHub returned an unsupported blob encoding");
  }
  const bytes = Buffer.from(blob.content.replace(/\\s/g, ""), "base64");
  if (bytes.length > maxFileBytes) throw new Error("GitHub source exceeds configured ingestion size limit");
  const gitBlobSha = createHash("sha1")
    .update(Buffer.concat([Buffer.from(`blob ${bytes.length}\\0`), bytes]))
    .digest("hex");
  if (gitBlobSha.toLowerCase() !== expectedBlobSha.toLowerCase()) {
    throw new Error("Git blob integrity check failed");
  }
  const content = bytes.toString("utf8");
  return ingestText({
    text: content,
    source: `github:${repo}@blob:${gitBlobSha}:${safePath}`,
    metadata: { repository: repo, ref, path: safePath, git_blob_sha: gitBlobSha, source: "github-git-blobs-api", integrity_verified: true }
  });
}

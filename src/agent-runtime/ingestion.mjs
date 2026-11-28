// CRYPTIC Agent Runtime — provenance-preserving local ingestion
// This records source material; it does NOT train or fine-tune a model.

import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile, realpath, stat, readdir, lstat, writeFile } from "node:fs/promises";
import path from "node:path";

const allowedExtensions = new Set([
  ".md", ".txt", ".json", ".yaml", ".yml", ".toml",
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".sh", ".ps1", ".html", ".css", ".sql"
]);
const blockedSegments = new Set([
  ".git", "node_modules", ".venv", "venv", ".next", "dist",
  "secrets", "credentials", "private", "vendor", "cryptic-ingest"
]);
const blockedNames = /(^\.env($|\.)|(^|\.)id_rsa$|\.pem$|\.p12$|\.pfx$|\.key$|secret|credential|token|password)/i;
const maxFileBytes = Number(process.env.CRYPTIC_INGEST_MAX_FILE_BYTES || 1048576);
const chunkChars = Number(process.env.CRYPTIC_INGEST_CHUNK_CHARS || 6000);
const overlapChars = Number(process.env.CRYPTIC_INGEST_OVERLAP_CHARS || 400);

const rootPath = () => path.resolve(process.env.CRYPTIC_INGEST_ROOT || process.cwd());
const storePath = () => path.resolve(process.env.CRYPTIC_INGEST_DIR || path.join(process.cwd(), "var", "cryptic-ingest"));
const ledgerPath = () => path.join(storePath(), "observations.jsonl");

function digest(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function splitChunks(text) {
  const chunks = [];
  const step = Math.max(1, chunkChars - overlapChars);
  for (let start = 0; start < text.length; start += step) {
    chunks.push(text.slice(start, start + chunkChars));
    if (start + chunkChars >= text.length) break;
  }
  return chunks;
}

async function appendObservation({ source, text, mediaType = "text/plain", metadata = {} }) {
  if (typeof text !== "string" || text.length === 0) throw new TypeError("Non-empty text is required");
  if (Buffer.byteLength(text, "utf8") > maxFileBytes) throw new Error("Ingestion payload exceeds configured size limit");
  await mkdir(storePath(), { recursive: true });
  const sourceDigest = digest(text);
  const chunks = splitChunks(text);
  const ingestedAt = new Date().toISOString();
  const records = chunks.map((content, index) => ({
    schema: "cryptic.observation.v1",
    observation_id: randomUUID(),
    ingested_at: ingestedAt,
    source,
    source_sha256: sourceDigest,
    media_type: mediaType,
    chunk_index: index,
    chunk_count: chunks.length,
    content,
    metadata
  }));
  await appendFile(ledgerPath(), records.map(record => JSON.stringify(record)).join("\n") + "\n", { encoding: "utf8", mode: 0o600 });
  return {
    accepted: true,
    source,
    source_sha256: sourceDigest,
    chunk_count: records.length,
    ingested_at: ingestedAt,
    ledger: ledgerPath()
  };
}

export async function ingestText({ text, source = "operator:text", metadata = {} }) {
  return appendObservation({ source: String(source).slice(0, 500), text, metadata });
}

export async function ingestFile({ relativePath }) {
  if (typeof relativePath !== "string" || !relativePath.trim()) throw new TypeError("relative_path is required");
  if (path.isAbsolute(relativePath)) throw new Error("Absolute paths are not accepted");
  const normalized = path.normalize(relativePath);
  const segments = normalized.split(/[\\/]+/).filter(Boolean);
  if (segments.some(segment => blockedSegments.has(segment.toLowerCase()) || blockedNames.test(segment))) {
    throw new Error("Path is excluded by the ingestion safety policy");
  }

  const root = await realpath(rootPath());
  const candidate = path.resolve(root, normalized);
  const relative = path.relative(root, candidate);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Path must resolve to a file inside CRYPTIC_INGEST_ROOT");
  }

  const actualPath = await realpath(candidate);
  const actualRelative = path.relative(root, actualPath);
  if (actualRelative.startsWith("..") || path.isAbsolute(actualRelative)) {
    throw new Error("Symlink target escapes the ingestion root");
  }
  if (blockedNames.test(path.basename(actualPath))) throw new Error("File name is excluded by the ingestion safety policy");
  const extension = path.extname(actualPath).toLowerCase();
  if (!allowedExtensions.has(extension)) throw new Error(`File extension is not ingestible: ${extension || "(none)"}`);

  const info = await stat(actualPath);
  if (!info.isFile()) throw new Error("Only regular files can be ingested");
  if (info.size > maxFileBytes) throw new Error(`File exceeds ${maxFileBytes} byte limit`);

  const text = await readFile(actualPath, "utf8");
  return appendObservation({
    source: `file:${actualRelative.split(path.sep).join("/")}`,
    text,
    mediaType: extension,
    metadata: { relative_path: actualRelative.split(path.sep).join("/"), bytes: info.size }
  });
}


export async function buildRepositoryManifest({ maxFiles = 5000, maxTotalBytes = 104857600 } = {}) {
  const root = await realpath(rootPath());
  const entries = [];
  const skipped = { excluded_path: 0, unsupported_type: 0, unsupported_extension: 0, oversized: 0, unreadable: 0 };
  let totalBytes = 0;
  let truncated = false;

  async function walk(directory) {
    if (entries.length >= maxFiles || totalBytes >= maxTotalBytes) {
      truncated = true;
      return;
    }
    let children;
    try { children = await readdir(directory, { withFileTypes: true }); }
    catch { skipped.unreadable++; return; }

    children.sort((a, b) => a.name.localeCompare(b.name));
    for (const child of children) {
      if (entries.length >= maxFiles || totalBytes >= maxTotalBytes) {
        truncated = true;
        break;
      }
      if (blockedSegments.has(child.name.toLowerCase()) || blockedNames.test(child.name)) {
        skipped.excluded_path++;
        continue;
      }
      const absolute = path.join(directory, child.name);
      let info;
      try { info = await lstat(absolute); }
      catch { skipped.unreadable++; continue; }
      if (info.isSymbolicLink()) {
        skipped.excluded_path++;
        continue;
      }
      if (info.isDirectory()) {
        await walk(absolute);
        continue;
      }
      if (!info.isFile()) {
        skipped.unsupported_type++;
        continue;
      }
      const extension = path.extname(child.name).toLowerCase();
      if (!allowedExtensions.has(extension)) {
        skipped.unsupported_extension++;
        continue;
      }
      if (info.size > maxFileBytes || totalBytes + info.size > maxTotalBytes) {
        skipped.oversized++;
        continue;
      }
      try {
        const content = await readFile(absolute);
        const relativePath = path.relative(root, absolute).split(path.sep).join("/");
        entries.push({
          path: relativePath,
          bytes: info.size,
          sha256: createHash("sha256").update(content).digest("hex"),
          extension,
          modified_at: info.mtime.toISOString()
        });
        totalBytes += info.size;
      } catch {
        skipped.unreadable++;
      }
    }
  }

  await walk(root);
  entries.sort((a, b) => a.path.localeCompare(b.path));
  const createdAt = new Date().toISOString();
  const canonical = JSON.stringify(entries);
  const manifest = {
    schema: "cryptic.repository-manifest.v1",
    created_at: createdAt,
    root_label: path.basename(root),
    file_count: entries.length,
    total_bytes: totalBytes,
    truncated,
    skipped,
    entries,
    manifest_sha256: digest(canonical)
  };
  await mkdir(storePath(), { recursive: true });
  const destination = path.join(storePath(), "repository-manifest.json");
  await writeFile(destination, JSON.stringify(manifest, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
  return {
    created: true,
    manifest: destination,
    manifest_sha256: manifest.manifest_sha256,
    file_count: manifest.file_count,
    total_bytes: manifest.total_bytes,
    truncated: manifest.truncated,
    skipped: manifest.skipped,
    preview: entries.slice(0, 20)
  };
}

export async function ingestionStatus() {
  try {
    const info = await stat(ledgerPath());
    const raw = await readFile(ledgerPath(), "utf8");
    return {
      configured: true,
      ledger: ledgerPath(),
      bytes: info.size,
      observation_chunks: raw.split("\n").filter(Boolean).length
    };
  } catch (error) {
    if (error.code === "ENOENT") return { configured: true, ledger: ledgerPath(), bytes: 0, observation_chunks: 0 };
    throw error;
  }
}

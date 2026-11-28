# CRYPTIC Golem Runtime — Model API, MCP, and Provenance Ingestion

**[SS][TDOC-META-WRAPPER-V13-§-CRYPTIC-GOLEM-RUNTIME]**  
**Status:** Initial implementation scaffold committed to a review branch; local execution and MCP-client conformance still require verification.  
**Canonical owner:** Azazeleous / CRYPTIC  
**Runtime:** Node.js 20+, built-in modules only

## Purpose

Establish CRYPTIC as the independent runtime foundation for the Golem: a model-agnostic agent interface with an OpenAI-compatible chat API, a stateless MCP HTTP endpoint, and provenance-preserving ingestion tools.

The Golem is an agent identity/workflow, not a proprietary model. It can use Ollama locally, another OpenAI-compatible provider, or a future provider adapter without changing the MCP tool contract.

## Responsibility boundaries

- **CRYPTIC:** canonical provider adapters, API/MCP runtime, ingestion, provenance, verification, model and extension contracts.
- **Golem:** agent profile, task planning, repository understanding, and controlled invocation of CRYPTIC tools.
- **Azazeleous/-z-m:** master profile registry, cross-project workflow registration, and device/runtime integration.
- **Sovereign-Operating-System:** desktop/terminal execution surface and future agent-host adapter.

## Runtime topology

```text
Architect / CLI / IDE
        |
        v
Golem compatibility client
        |
        +---- OpenAI-compatible API: /v1/chat/completions
        |              |
        |              v
        |        Provider adapter
        |          |       |
        |        Ollama  OpenAI-compatible endpoint
        |
        +---- MCP Streamable HTTP profile: POST /mcp
                       |
                 CRYPTIC tools
                  |          |
              ingest_text  ingest_file
                  |          |
                  +---- provenance ledger
                             |
                      local JSONL store
```

## Implemented in this branch

- `src/agent-runtime/provider.mjs`: OpenAI-compatible provider adapter; defaults to Ollama at `127.0.0.1:11434/v1` and `llama3.2:1b`.
- `src/agent-runtime/ingestion.mjs`: bounded local repository manifest generation, text and allowlisted source-file ingestion; SHA-256 source digests; chunk records; append-only JSONL observations.\n- `src/agent-runtime/github-ingest.mjs`: read-only GitHub tree manifests and selected-file ingestion, gated by a repository allowlist and a fine-grained read-only token.
- `src/agent-runtime/server.mjs`: local HTTP server exposing `/healthz`, `/v1/models`, `/v1/chat/completions`, and `POST /mcp`.

The MCP endpoint implements a deliberately small stateless JSON-RPC tool profile: `initialize`, `ping`, `tools/list`, and `tools/call`. Its tools are `cryptic_status`, `build_repository_manifest`, `github_repository_manifest`, `github_ingest_file` (requires the manifest path and `expected_blob_sha`), `ingest_file`, and `ingest_text`. It does not claim support for MCP resources, prompts, SSE streaming, session resumption, or the complete SDK feature set. Adopt the official MCP SDK when those features become requirements.

## Start locally

From the repository root:

```bash
node --version
# Node.js 20 or newer
CRYPTIC_PROVIDER_BASE_URL=http://127.0.0.1:11434/v1 \
CRYPTIC_MODEL=llama3.2:1b \
node src/agent-runtime/server.mjs
```

Optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `CRYPTIC_BIND_HOST` | `127.0.0.1` | Bind address; non-loopback requires a bearer token |
| `CRYPTIC_PORT` | `8765` | Runtime port |
| `CRYPTIC_MCP_TOKEN` | empty | Optional bearer token; mandatory for non-loopback binding |
| `CRYPTIC_PROVIDER_BASE_URL` | `http://127.0.0.1:11434/v1` | Ollama or compatible provider base |
| `CRYPTIC_PROVIDER_API_KEY` | empty | Provider credential, supplied only through environment |
| `CRYPTIC_MODEL` | `llama3.2:1b` | Default model identifier |
| `CRYPTIC_INGEST_ROOT` | current working directory | Root allowed for relative file ingestion |
| `CRYPTIC_INGEST_DIR` | `./var/cryptic-ingest` | Local provenance ledger directory |\n| `CRYPTIC_GITHUB_TOKEN` | empty | Fine-grained GitHub token with Contents: Read-only on selected repositories |\n| `CRYPTIC_GITHUB_ALLOWED_REPOS` | empty | Comma-separated exact `owner/repo` allowlist; empty means GitHub ingestion is disabled |\n| `CRYPTIC_GITHUB_MAX_FILE_BYTES` | `1048576` | Maximum selected GitHub file size |\n| `CRYPTIC_GITHUB_MANIFEST_MAX_FILES` | `2000` | Maximum manifest entries returned |

Do not expose this service directly to the public internet. For remote device access, place it behind an authenticated encrypted overlay and retain application-level authorization. Do not put credentials in Git.

## Smoke checks

```bash
curl -fsS http://127.0.0.1:8765/healthz

curl -fsS http://127.0.0.1:8765/v1/models

curl -fsS http://127.0.0.1:8765/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2:1b","messages":[{"role":"user","content":"Reply with CRYPTIC runtime online."}],"stream":false}'

curl -fsS http://127.0.0.1:8765/mcp \
  -X POST -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cryptic-smoke","version":"0.1.0"}}}'

curl -fsS http://127.0.0.1:8765/mcp \
  -X POST -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## Golem ingestion contract

The Golem should first call `github_repository_manifest` for an explicitly allowlisted GitHub repository (or `build_repository_manifest` for a local checkout). The GitHub tool reads repository tree metadata only and returns a bounded manifest with file paths, sizes, extensions, Git blob identifiers, and a manifest digest. It does not download file contents. The Golem may then request individual selected files through `github_ingest_file`, passing the `git_blob_sha` returned by the manifest. The adapter fetches that immutable Git blob, independently verifies its Git SHA-1 object identifier, then computes the SHA-256 content digest in the shared provenance ledger. This prevents a branch moving between manifest creation and file retrieval from silently changing the selected source. For local checkouts, the local manifest tool skips symlinks and excluded directories. Both paths support selected-source ingestion through `ingest_file` or `ingest_text`.

Each accepted source is represented by:
- source label or repository-relative path;
- retrieval/ingestion timestamp;
- SHA-256 digest of the original text;
- media type and chunk index/count;
- metadata supplied by the caller;
- exact text chunk stored in the local append-only JSONL ledger.

The first version does not automatically crawl or ingest every remote repository. It can inspect an explicitly allowlisted GitHub tree, then ingest only individually selected files. It does not execute ingested code, create embeddings, fine-tune weights, or grant permissions. Repository acquisition, indexing, embedding, training, and tool authorization are separate stages with separate evidence.

## Security and trust boundaries

- Default bind is loopback only.
- Non-loopback binding is refused unless `CRYPTIC_MCP_TOKEN` is set.
- Provider credentials and the GitHub read token are read from environment variables, never source files.\n- GitHub ingestion is disabled unless both `CRYPTIC_GITHUB_TOKEN` and an exact `CRYPTIC_GITHUB_ALLOWED_REPOS` allowlist are configured. Use a fine-grained token with Contents: Read-only only.
- No arbitrary shell, browser, network-fetch, or unrestricted filesystem tool is exposed.
- File ingestion is relative to an explicit root, extension-allowlisted, size-limited, and rejects secret-like names, excluded directories, and symlink escapes.
- Ingestion records are data, not executable instructions. Prompt injection found in source material must remain untrusted input.
- The local JSONL ledger is append-only by application behavior, not tamper-proof storage. A later hardening stage should add signed manifests, hash chaining, external anchoring, retention policy, and independent verification.
- This initial runtime is not yet production-certified. Require tests, MCP client interoperability checks, auth/rate-limit review, and deployment hardening before remote exposure.

## Evolution plan

1. **V1 — Runtime/API/MCP:** local model adapter, tool endpoint, provenance ingestion (this branch).
2. **V2 — Golem repository reader:** bounded GitHub tree manifests and selected-file ingestion are scaffolded here; add revision-pinned resumable checkpoints, `.gitignore` parity, and signed acquisition receipts.
3. **V3 — Knowledge index:** chunk deduplication, embedding adapter, vector/hybrid search, source citations.
4. **V4 — Agent execution:** typed tools, policy scopes, human approval, task ledger, and recovery.
5. **V5 — Multi-node fabric:** Termux and GAIA's Window adapters, authenticated transport, signed sync receipts.
6. **V6 — Model creation:** dataset curation, evaluation harness, reproducible fine-tuning/training jobs, model artifact registry, and provenance-bound releases.

## Acceptance criteria before calling this operational

- Node syntax checks pass for every module.
- Local Ollama request returns a real provider response.
- A compatible MCP client completes initialize, tools/list, and tools/call.
- Path traversal, symlink escape, secret-name, oversized file, and malformed JSON tests pass.
- A restart preserves prior ingestion records.
- No credential appears in the repository or logs.
- Status labels remain evidence-based: documented, implemented, tested, configured, healthy, integrated.

---

**The Architect / Nexus / Cryptic News LLC / Project: The Nexus Generation: GaiaSSoul / SERIES: The Nexus of Gaia / ID: 137451921129154222|040592|433855274**

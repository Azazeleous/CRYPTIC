// CRYPTIC Agent Runtime — local OpenAI-compatible API + stateless MCP endpoint
// Node.js 20+. Built-in modules only. Default bind is loopback.
// MCP subset: initialize, ping, tools/list, tools/call. No arbitrary shell tool.

import http from "node:http";
import { createChatCompletion, listModels, providerConfig } from "./provider.mjs";
import { buildRepositoryManifest, ingestFile, ingestText, ingestionStatus } from "./ingestion.mjs";

const host = process.env.CRYPTIC_BIND_HOST || "127.0.0.1";
const port = Number(process.env.CRYPTIC_PORT || 8765);
const token = process.env.CRYPTIC_MCP_TOKEN || "";
const isLoopback = host === "127.0.0.1" || host === "::1" || host === "localhost";
if (!isLoopback && !token) {
  throw new Error("Refusing non-loopback bind without CRYPTIC_MCP_TOKEN");
}

const tools = [
  {
    name: "cryptic_status",
    description: "Return runtime/provider configuration and local ingestion ledger status. Does not expose secrets.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "ingest_text",
    description: "Record operator-supplied text with SHA-256 provenance and chunk metadata. This does not train a model.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", minLength: 1, maxLength: 250000 },
        source: { type: "string", maxLength: 500 },
        metadata: { type: "object" }
      },
      required: ["text"],
      additionalProperties: false
    }
  },
  {
    name: "ingest_file",
    description: "Ingest one allowlisted text/code file relative to CRYPTIC_INGEST_ROOT. Secret-like paths, binary files, symlink escapes, and oversized files are rejected.",
    inputSchema: {
      type: "object",
      properties: { relative_path: { type: "string", minLength: 1, maxLength: 1000 } },
      required: ["relative_path"],
      additionalProperties: false
    }
  },
  {
    name: "build_repository_manifest",
    description: "Build a bounded, hash-verified inventory of allowlisted repository files under CRYPTIC_INGEST_ROOT. Does not ingest file contents or follow symlinks.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  }
];

function sendJson(res, status, payload, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(payload));
}

async function readJson(req, limit = 1024 * 1024) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > limit) throw Object.assign(new Error("Request body too large"), { statusCode: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw Object.assign(new Error("Request body must be valid JSON"), { statusCode: 400 }); }
}

function authorized(req) {
  if (!token) return isLoopback;
  return req.headers.authorization === `Bearer ${token}`;
}

function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

async function handleTool(name, args = {}) {
  if (name === "cryptic_status") {
    return { runtime: "cryptic-agent-runtime", version: "0.1.0", provider: providerConfig(), ingestion: await ingestionStatus() };
  }
  if (name === "ingest_text") {
    return ingestText({ text: args.text, source: args.source, metadata: args.metadata || {} });
  }
  if (name === "ingest_file") {
    return ingestFile({ relativePath: args.relative_path });
  }
  if (name === "build_repository_manifest") {
    return buildRepositoryManifest();
  }
  throw new Error(`Unknown tool: ${name}`);
}

async function handleMcp(req, res) {
  const message = await readJson(req);
  if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    return sendJson(res, 400, rpcError(message?.id, -32600, "Invalid JSON-RPC request"));
  }
  if (message.method.startsWith("notifications/")) {
    res.writeHead(202, { "Cache-Control": "no-store" });
    return res.end();
  }

  let result;
  try {
    switch (message.method) {
      case "initialize":
        result = {
          protocolVersion: "2025-03-26",
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "cryptic-agent-runtime", version: "0.1.0" }
        };
        break;
      case "ping":
        result = {};
        break;
      case "tools/list":
        result = { tools };
        break;
      case "tools/call": {
        const name = message.params?.name;
        const args = message.params?.arguments || {};
        try {
          const value = await handleTool(name, args);
          result = { content: [{ type: "text", text: JSON.stringify(value, null, 2) }], structuredContent: value, isError: false };
        } catch (error) {
          result = { content: [{ type: "text", text: error.message }], isError: true };
        }
        break;
      }
      default:
        return sendJson(res, 200, rpcError(message.id, -32601, `Method not found: ${message.method}`));
    }
    return sendJson(res, 200, { jsonrpc: "2.0", id: message.id ?? null, result });
  } catch (error) {
    return sendJson(res, 200, rpcError(message.id, -32603, error.message));
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (!authorized(req)) return sendJson(res, 401, { error: "unauthorized" });
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

    if (req.method === "GET" && url.pathname === "/healthz") {
      return sendJson(res, 200, { ok: true, service: "cryptic-agent-runtime", version: "0.1.0", provider: providerConfig() });
    }
    if (req.method === "GET" && url.pathname === "/v1/models") {
      try { return sendJson(res, 200, await listModels()); }
      catch (error) { return sendJson(res, 502, { error: { message: error.message, type: "provider_error" } }); }
    }
    if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = await readJson(req);
      try { return sendJson(res, 200, await createChatCompletion(body)); }
      catch (error) { return sendJson(res, 502, { error: { message: error.message, type: "provider_error" } }); }
    }
    if (req.method === "POST" && url.pathname === "/mcp") {
      return await handleMcp(req, res);
    }
    if (url.pathname === "/mcp") {
      res.setHeader("Allow", "POST");
      return sendJson(res, 405, { error: "method_not_allowed" });
    }
    return sendJson(res, 404, { error: "not_found" });
  } catch (error) {
    return sendJson(res, error.statusCode || 500, { error: error.message || "internal_error" });
  }
});

server.listen(port, host, () => {
  process.stdout.write(`CRYPTIC Agent Runtime listening on http://${host}:${port}\n`);
  process.stdout.write(`Provider: ${providerConfig().base_url} | Model: ${providerConfig().model}\n`);
});

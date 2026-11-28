// CRYPTIC Agent Runtime — OpenAI-compatible provider adapter
// Supports Ollama's /v1/chat/completions and compatible endpoints.
// No provider key is embedded in source.

const baseUrl = () => (process.env.CRYPTIC_PROVIDER_BASE_URL || "http://127.0.0.1:11434/v1").replace(/\/+$/, "");
const modelName = () => process.env.CRYPTIC_MODEL || "llama3.2:1b";

export function providerConfig() {
  return {
    base_url: baseUrl(),
    model: modelName(),
    api_key_configured: Boolean(process.env.CRYPTIC_PROVIDER_API_KEY)
  };
}

export async function listModels() {
  const headers = {};
  if (process.env.CRYPTIC_PROVIDER_API_KEY) {
    headers.Authorization = `Bearer ${process.env.CRYPTIC_PROVIDER_API_KEY}`;
  }
  const response = await fetch(`${baseUrl()}/models`, { headers, signal: AbortSignal.timeout(15000) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`Provider models request failed (${response.status}): ${JSON.stringify(payload)}`);
  return payload;
}

export async function createChatCompletion(input) {
  if (!input || !Array.isArray(input.messages)) {
    throw new TypeError("messages must be an array");
  }
  if (input.stream === true) {
    throw new Error("Streaming is not implemented in this first runtime version; set stream=false.");
  }

  const headers = { "Content-Type": "application/json" };
  if (process.env.CRYPTIC_PROVIDER_API_KEY) {
    headers.Authorization = `Bearer ${process.env.CRYPTIC_PROVIDER_API_KEY}`;
  }

  const body = {
    model: input.model || modelName(),
    messages: input.messages,
    stream: false
  };
  for (const key of ["temperature", "top_p", "max_tokens", "stop", "tools", "tool_choice", "response_format"]) {
    if (input[key] !== undefined) body[key] = input[key];
  }

  const response = await fetch(`${baseUrl()}/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(Number(process.env.CRYPTIC_PROVIDER_TIMEOUT_MS || 120000))
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`Provider chat request failed (${response.status}): ${JSON.stringify(payload)}`);
  return payload;
}

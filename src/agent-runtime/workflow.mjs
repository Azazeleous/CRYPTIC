// Typed, plan-only workflow DAG for Golem.
// This module never invokes a shell or executes a planned capability.

const CAPABILITIES = [
  { id: "cryptic.status", risk: "read", description: "Inspect runtime and ingestion status." },
  { id: "local.repository_manifest", risk: "read", description: "Build a bounded local repository manifest." },
  { id: "github.repository_manifest", risk: "read", description: "Read an allowlisted GitHub tree manifest." },
  { id: "local.ingest_file", risk: "write_local", description: "Append selected local file provenance." },
  { id: "local.ingest_text", risk: "write_local", description: "Append operator-supplied text provenance." },
  { id: "github.ingest_file", risk: "write_local", description: "Fetch and append one immutable GitHub blob." }
];

const CAPABILITY_MAP = new Map(CAPABILITIES.map((item) => [item.id, item]));

export function listCapabilities() {
  return CAPABILITIES.map((item) => ({ ...item }));
}

export function buildWorkflowPlan(input = {}) {
  const steps = input.steps;
  if (!Array.isArray(steps) || steps.length < 1 || steps.length > 64) {
    throw new Error("steps must be an array containing 1 to 64 workflow steps");
  }

  const byId = new Map();
  for (const step of steps) {
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      throw new Error("each workflow step must be an object");
    }
    if (typeof step.id !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(step.id)) {
      throw new Error("step id is invalid");
    }
    if (byId.has(step.id)) throw new Error("duplicate step id: " + step.id);
    if (typeof step.capability !== "string" || !CAPABILITY_MAP.has(step.capability)) {
      throw new Error("unregistered capability in step " + step.id);
    }
    const dependencies = step.depends_on === undefined ? [] : step.depends_on;
    if (!Array.isArray(dependencies) || dependencies.some((value) => typeof value !== "string")) {
      throw new Error("depends_on must be an array of step ids");
    }
    byId.set(step.id, {
      id: step.id,
      capability: step.capability,
      depends_on: [...new Set(dependencies)],
      inputs: step.inputs && typeof step.inputs === "object" && !Array.isArray(step.inputs) ? step.inputs : {}
    });
  }

  for (const step of byId.values()) {
    for (const dependency of step.depends_on) {
      if (!byId.has(dependency)) {
        throw new Error("unknown dependency " + dependency + " referenced by " + step.id);
      }
      if (dependency === step.id) throw new Error("step cannot depend on itself: " + step.id);
    }
  }

  const indegree = new Map();
  const children = new Map();
  for (const step of byId.values()) {
    indegree.set(step.id, step.depends_on.length);
    children.set(step.id, []);
  }
  for (const step of byId.values()) {
    for (const dependency of step.depends_on) children.get(dependency).push(step.id);
  }

  const ready = [...byId.keys()].filter((id) => indegree.get(id) === 0).sort();
  const order = [];
  while (ready.length) {
    const id = ready.shift();
    order.push(id);
    for (const child of children.get(id)) {
      indegree.set(child, indegree.get(child) - 1);
      if (indegree.get(child) === 0) {
        ready.push(child);
        ready.sort();
      }
    }
  }
  if (order.length !== byId.size) throw new Error("workflow contains a dependency cycle");

  const stages = order.map((id, index) => {
    const step = byId.get(id);
    const capability = CAPABILITY_MAP.get(step.capability);
    return {
      sequence: index + 1,
      id: step.id,
      capability: capability.id,
      depends_on: step.depends_on,
      risk: capability.risk,
      approval_required: capability.risk !== "read",
      inputs_present: Object.keys(step.inputs).length > 0
    };
  });

  return {
    planner: "cryptic-golem-dag",
    planner_version: "0.1.0",
    execution: "plan_only",
    step_count: stages.length,
    order,
    stages,
    policy: {
      unknown_capabilities: "reject",
      dependency_cycles: "reject",
      model_generated_shell: "never_execute",
      write_capabilities: "approval_required"
    }
  };
}

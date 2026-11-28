import test from "node:test";
import assert from "node:assert/strict";
import { buildWorkflowPlan, listCapabilities } from "./workflow.mjs";

test("capability registry exposes only declared capabilities", () => {
  const items = listCapabilities();
  assert.ok(items.some((item) => item.id === "github.repository_manifest"));
  assert.ok(items.every((item) => typeof item.risk === "string"));
});

test("workflow planner orders prerequisites before dependents", () => {
  const plan = buildWorkflowPlan({
    steps: [
      { id: "ingest", capability: "github.ingest_file", depends_on: ["manifest"] },
      { id: "manifest", capability: "github.repository_manifest" }
    ]
  });
  assert.deepEqual(plan.order, ["manifest", "ingest"]);
  assert.equal(plan.execution, "plan_only");
  assert.equal(plan.stages[1].approval_required, true);
});

test("workflow planner rejects unknown capabilities", () => {
  assert.throws(() => buildWorkflowPlan({
    steps: [{ id: "bad", capability: "shell.execute" }]
  }), /unregistered capability/);
});

test("workflow planner rejects missing dependencies", () => {
  assert.throws(() => buildWorkflowPlan({
    steps: [{ id: "a", capability: "cryptic.status", depends_on: ["missing"] }]
  }), /unknown dependency/);
});

test("workflow planner rejects dependency cycles", () => {
  assert.throws(() => buildWorkflowPlan({
    steps: [
      { id: "a", capability: "cryptic.status", depends_on: ["b"] },
      { id: "b", capability: "cryptic.status", depends_on: ["a"] }
    ]
  }), /dependency cycle/);
});

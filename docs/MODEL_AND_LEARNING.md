# Model and Learning Architecture

Separate model inference from training and from tool execution.

Core interfaces:
- ModelProvider: metadata, capabilities, context limits, inference, cancellation.
- ModelRouter: task classification, policy, availability, latency, cost, quality.
- MemoryStore: provenance-aware facts and user-approved durable context.
- Retrieval: indexed documents with source citations and access controls.
- Planner: typed task graph and bounded execution.
- Evaluator: held-out tests, quality metrics, calibration, regressions.
- Trainer: curated datasets, reproducible configuration, checkpoint lineage.

Local-first operation is preferred where hardware permits. External providers may require accounts, credentials, licensing, or network access. “Maximum learning” means measured improvement on defined evaluations, not unbounded self-modification.

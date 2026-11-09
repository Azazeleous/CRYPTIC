# Operations

Required operational signals:
- source connectivity and last successful probe
- ingestion lag, throughput, queue depth, backpressure
- schema rejection and source discrepancy rates
- storage bytes, chunk verification, replication and recovery status
- model latency, failure, resource use, evaluation regression
- extension sandbox failures and permission changes
- device enrollment, connectivity, and revoked credentials

Runbooks must define alert thresholds, diagnosis, bounded remediation, rollback, and evidence capture. Never report healthy based only on process liveness.

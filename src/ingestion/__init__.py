"""Read-only ingestion source contracts."""

from .observation_log import (
    ObservationJournalError,
    append_page,
    audit_journal,
    read_records,
)
from .json_rpc import (
    EvmReadOnlyAdapter,
    JsonRpcClient,
    JsonRpcError,
    JsonRpcPolicy,
    JsonRpcRemoteError,
    SolanaReadOnlyAdapter,
)
from .source_registry import (
    HealthReport,
    SourceAdapter,
    SourceAdapterError,
    SourceDescriptor,
    SourcePage,
    SourceRegistry,
    SourceRegistryError,
)

__all__ = [
    "ObservationJournalError",
    "append_page",
    "audit_journal",
    "read_records",
    "EvmReadOnlyAdapter",
    "JsonRpcClient",
    "JsonRpcError",
    "JsonRpcPolicy",
    "JsonRpcRemoteError",
    "SolanaReadOnlyAdapter",
    "HealthReport",
    "SourceAdapter",
    "SourceAdapterError",
    "SourceDescriptor",
    "SourcePage",
    "SourceRegistry",
    "SourceRegistryError",
]

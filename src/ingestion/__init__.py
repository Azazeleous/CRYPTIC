"""Read-only ingestion source contracts."""

from .asset_identity import (
    AmbiguousAssetAliasError,
    AssetAlias,
    AssetIdentity,
    AssetIdentityError,
    AssetNotFoundError,
    AssetRecord,
    AssetRegistry,
)
from .replay import ReplayError, replay_journal
from .runtime import (BoundedIngestionRuntime, DeadlineAwareAdapter, IngestionDeadlineExceeded, IngestionPolicy, IngestionRuntimeError)
from .normalization import (
    NormalizationError,
    compare_chain_heads,
    normalize_chain_observation,
    normalize_journal_record,
)
from .observation_log import (
    ObservationJournalError,
    append_page,
    audit_journal,
    read_records,
)
from .json_rpc import (
    EvmReadOnlyAdapter,
    JsonRpcClient,
    JsonRpcDeadlineExceeded,
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
    "AmbiguousAssetAliasError",
    "AssetAlias",
    "AssetIdentity",
    "AssetIdentityError",
    "AssetNotFoundError",
    "AssetRecord",
    "AssetRegistry",
    "BoundedIngestionRuntime",
    "DeadlineAwareAdapter",
    "IngestionDeadlineExceeded",
    "IngestionPolicy",
    "IngestionRuntimeError",
    "ReplayError",
    "replay_journal",
    "NormalizationError",
    "compare_chain_heads",
    "normalize_chain_observation",
    "normalize_journal_record",
    "ObservationJournalError",
    "append_page",
    "audit_journal",
    "read_records",
    "EvmReadOnlyAdapter",
    "JsonRpcClient",
    "JsonRpcDeadlineExceeded",
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

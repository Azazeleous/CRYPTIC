"""Canonical asset identity and collision-safe alias resolution.

Symbols and display names are aliases, never canonical identity. Identity is
scoped to a normalized network fingerprint and a chain-native asset reference.
This registry is process-local; persistence and provider enrollment are separate.
"""
from __future__ import annotations
from dataclasses import dataclass
import re
from threading import RLock
from typing import Iterable, Literal, Mapping

_ASSET_SCHEMA = "cryptic.normalized-chain-head.v1"
_NETWORK_ID = re.compile(r"^[0-9a-f]{64}$")
_EVM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALIAS_TYPES = frozenset({"symbol", "provider_id", "name"})
_SYMBOL = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,31}$")


class AssetIdentityError(ValueError):
    """Invalid asset identity, metadata, or alias operation."""


class AssetNotFoundError(LookupError):
    """No asset matches the requested network-scoped alias."""


class AmbiguousAssetAliasError(AssetIdentityError):
    """An alias is already bound to a different asset in the same scope."""


def _decode_base58(value: str) -> bytes:
    number = 0
    for char in value:
        try:
            digit = _BASE58.index(char)
        except ValueError as exc:
            raise AssetIdentityError("Solana mint must be base58") from exc
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return (b"\x00" * (len(value) - len(value.lstrip("1")))) + body


def _normalize_alias(alias_type: str, value: str) -> str:
    if alias_type not in _ALIAS_TYPES:
        raise AssetIdentityError("unsupported alias_type")
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise AssetIdentityError("alias value must be a non-empty string of at most 256 characters")
    value = value.strip()
    if alias_type == "symbol":
        normalized = value.upper()
        if not _SYMBOL.fullmatch(normalized):
            raise AssetIdentityError("symbol contains unsupported characters")
        return normalized
    if alias_type == "name":
        return " ".join(value.casefold().split())
    return value


@dataclass(frozen=True, slots=True)
class AssetIdentity:
    """Network-scoped identity independent of ticker, name, or provider."""
    network_family: Literal["evm", "solana"]
    network_identity: str
    asset_reference: str

    def validate(self) -> None:
        if self.network_family not in {"evm", "solana"}:
            raise AssetIdentityError("network_family must be evm or solana")
        if not isinstance(self.network_identity, str) or not _NETWORK_ID.fullmatch(self.network_identity):
            raise AssetIdentityError("network_identity must be a lowercase SHA-256 fingerprint")
        if not isinstance(self.asset_reference, str):
            raise AssetIdentityError("asset_reference must be a string")
        if self.asset_reference == "native":
            return
        if self.network_family == "evm":
            if not _EVM_ADDRESS.fullmatch(self.asset_reference):
                raise AssetIdentityError("EVM asset_reference must be a 20-byte contract address")
        else:
            if not 32 <= len(self.asset_reference) <= 44 or len(_decode_base58(self.asset_reference)) != 32:
                raise AssetIdentityError("Solana asset_reference must be a 32-byte base58 mint")

    @property
    def canonical_id(self) -> str:
        self.validate()
        reference = self.asset_reference.lower() if self.network_family == "evm" and self.asset_reference != "native" else self.asset_reference
        return f"cryptic:asset:v1:{self.network_family}:{self.network_identity}:{reference}"

    @classmethod
    def from_normalized_chain(cls, observation: Mapping[str, object], asset_reference: str) -> "AssetIdentity":
        if not isinstance(observation, Mapping) or observation.get("schema") != _ASSET_SCHEMA:
            raise AssetIdentityError("a normalized chain-head observation is required")
        identity = cls(observation.get("network_family"), observation.get("network_identity"), asset_reference)  # type: ignore[arg-type]
        identity.validate()
        return identity


@dataclass(frozen=True, slots=True)
class AssetAlias:
    alias_type: Literal["symbol", "provider_id", "name"]
    value: str
    source_id: str | None = None

    def normalized(self) -> tuple[str, str, str]:
        alias = _normalize_alias(self.alias_type, self.value)
        source = self.source_id
        if source is not None and (not isinstance(source, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", source)):
            raise AssetIdentityError("source_id must be lowercase and URL-safe")
        if self.alias_type == "provider_id" and source is None:
            raise AssetIdentityError("provider_id aliases require a source_id")
        return self.alias_type, alias, source or ""


@dataclass(frozen=True, slots=True)
class AssetRecord:
    identity: AssetIdentity
    symbol: str | None = None
    name: str | None = None
    decimals: int | None = None

    def validate(self) -> None:
        self.identity.validate()
        if self.symbol is not None and _normalize_alias("symbol", self.symbol) != self.symbol:
            raise AssetIdentityError("symbol metadata must be uppercase and canonical")
        if self.name is not None and (not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 128):
            raise AssetIdentityError("name must contain 1 to 128 characters")
        if self.decimals is not None and (isinstance(self.decimals, bool) or not isinstance(self.decimals, int) or not 0 <= self.decimals <= 255):
            raise AssetIdentityError("decimals must be an integer between 0 and 255")


class AssetRegistry:
    """Thread-safe, deterministic registry with explicit alias-collision handling."""
    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[str, AssetRecord] = {}
        self._aliases: dict[tuple[str, str, str, str, str], str] = {}

    def register(self, identity: AssetIdentity, *, symbol: str | None = None, name: str | None = None, decimals: int | None = None, aliases: Iterable[AssetAlias] = ()) -> AssetRecord:
        record = AssetRecord(identity, symbol, name, decimals)
        record.validate()
        alias_items = list(aliases)
        if symbol is not None:
            alias_items.append(AssetAlias("symbol", symbol))
        if name is not None:
            alias_items.append(AssetAlias("name", name))
        prepared = [alias.normalized() for alias in alias_items]
        canonical_id = identity.canonical_id
        with self._lock:
            existing = self._records.get(canonical_id)
            if existing is not None and existing != record:
                raise AssetIdentityError("canonical asset metadata conflict")
            keys = [(identity.network_family, identity.network_identity, kind, value, source) for kind, value, source in prepared]
            for key in keys:
                mapped = self._aliases.get(key)
                if mapped is not None and mapped != canonical_id:
                    raise AmbiguousAssetAliasError(f"{key[2]} alias is already bound in this scope")
            self._records.setdefault(canonical_id, record)
            for key in keys:
                self._aliases[key] = canonical_id
            return self._records[canonical_id]

    def add_alias(self, identity: AssetIdentity, alias: AssetAlias) -> None:
        identity.validate()
        kind, value, source = alias.normalized()
        canonical_id = identity.canonical_id
        key = (identity.network_family, identity.network_identity, kind, value, source)
        with self._lock:
            if canonical_id not in self._records:
                raise AssetNotFoundError("asset must be registered before aliases are added")
            mapped = self._aliases.get(key)
            if mapped is not None and mapped != canonical_id:
                raise AmbiguousAssetAliasError(f"{kind} alias is already bound in this scope")
            self._aliases[key] = canonical_id

    def get(self, identity: AssetIdentity) -> AssetRecord:
        canonical_id = identity.canonical_id
        with self._lock:
            try:
                return self._records[canonical_id]
            except KeyError as exc:
                raise AssetNotFoundError("canonical asset is not registered") from exc

    def resolve(self, *, network_family: Literal["evm", "solana"], network_identity: str, alias_type: Literal["symbol", "provider_id", "name"], value: str, source_id: str | None = None) -> AssetRecord:
        normalized = _normalize_alias(alias_type, value)
        if network_family not in {"evm", "solana"}:
            raise AssetIdentityError("unsupported network_family")
        if not isinstance(network_identity, str) or not _NETWORK_ID.fullmatch(network_identity):
            raise AssetIdentityError("network_identity must be a lowercase SHA-256 fingerprint")
        if source_id is not None and (not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", source_id)):
            raise AssetIdentityError("source_id must be lowercase and URL-safe")
        if alias_type == "provider_id" and source_id is None:
            raise AssetIdentityError("provider_id resolution requires a source_id")
        with self._lock:
            keys = []
            if source_id is not None:
                keys.append((network_family, network_identity, alias_type, normalized, source_id))
            keys.append((network_family, network_identity, alias_type, normalized, ""))
            mapped = next((self._aliases[key] for key in keys if key in self._aliases), None)
            if mapped is None:
                raise AssetNotFoundError("no asset matches this network-scoped alias")
            return self._records[mapped]

    def list_assets(self, *, network_family: Literal["evm", "solana"] | None = None, network_identity: str | None = None) -> tuple[AssetRecord, ...]:
        if network_family is not None and network_family not in {"evm", "solana"}:
            raise AssetIdentityError("unsupported network_family")
        if network_identity is not None and not _NETWORK_ID.fullmatch(network_identity):
            raise AssetIdentityError("network_identity must be a lowercase SHA-256 fingerprint")
        with self._lock:
            records = [record for record in self._records.values() if (network_family is None or record.identity.network_family == network_family) and (network_identity is None or record.identity.network_identity == network_identity)]
            return tuple(sorted(records, key=lambda item: item.identity.canonical_id))


__all__ = ["AmbiguousAssetAliasError", "AssetAlias", "AssetIdentity", "AssetIdentityError", "AssetNotFoundError", "AssetRecord", "AssetRegistry"]

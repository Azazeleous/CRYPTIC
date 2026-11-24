"""Canonical asset identity and durable, collision-safe alias registry."""
from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3
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
    if not isinstance(alias_type, str) or alias_type not in _ALIAS_TYPES:
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
        if not isinstance(self.network_family, str) or self.network_family not in {"evm", "solana"}:
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
        elif not 32 <= len(self.asset_reference) <= 44 or len(_decode_base58(self.asset_reference)) != 32:
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
    """SQLite-backed, thread-safe registry with atomic alias binding.

    The default database is in-memory. Supply a filesystem path for durable
    records. File-backed databases use WAL and FULL synchronous commits.
    """
    def __init__(self, database_path: str = ":memory:") -> None:
        if not isinstance(database_path, str) or not database_path:
            raise AssetIdentityError("database_path must be a non-empty string")
        self._lock = RLock()
        self._closed = False
        self._db = sqlite3.connect(database_path, timeout=10, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA synchronous=FULL")
        if database_path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                canonical_id TEXT PRIMARY KEY,
                network_family TEXT NOT NULL,
                network_identity TEXT NOT NULL,
                asset_reference TEXT NOT NULL,
                symbol TEXT,
                name TEXT,
                decimals INTEGER,
                UNIQUE(network_family, network_identity, asset_reference)
            );
            CREATE TABLE IF NOT EXISTS aliases (
                network_family TEXT NOT NULL,
                network_identity TEXT NOT NULL,
                alias_type TEXT NOT NULL,
                alias_value TEXT NOT NULL,
                source_id TEXT NOT NULL,
                canonical_id TEXT NOT NULL REFERENCES assets(canonical_id) ON DELETE CASCADE,
                PRIMARY KEY(network_family, network_identity, alias_type, alias_value, source_id)
            );
            CREATE INDEX IF NOT EXISTS aliases_by_asset ON aliases(canonical_id);
        """)

    def _ensure_open(self) -> None:
        if self._closed:
            raise AssetIdentityError("asset registry is closed")

    @staticmethod
    def _record(row: tuple) -> AssetRecord:
        identity = AssetIdentity(row[1], row[2], row[3])
        return AssetRecord(identity, row[4], row[5], row[6])

    def register(self, identity: AssetIdentity, *, symbol: str | None = None, name: str | None = None, decimals: int | None = None, aliases: Iterable[AssetAlias] = ()) -> AssetRecord:
        identity.validate()
        normalized_identity = AssetIdentity(
            identity.network_family,
            identity.network_identity,
            identity.asset_reference.lower() if identity.network_family == "evm" and identity.asset_reference != "native" else identity.asset_reference,
        )
        record = AssetRecord(normalized_identity, symbol, name, decimals)
        record.validate()
        alias_items = list(aliases)
        if symbol is not None:
            alias_items.append(AssetAlias("symbol", symbol))
        if name is not None:
            alias_items.append(AssetAlias("name", name))
        prepared = [alias.normalized() for alias in alias_items]
        canonical_id = normalized_identity.canonical_id
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT canonical_id, network_family, network_identity, asset_reference, symbol, name, decimals FROM assets WHERE canonical_id=?",
                    (canonical_id,),
                ).fetchone()
                if existing is not None and self._record(existing) != record:
                    raise AssetIdentityError("canonical asset metadata conflict")
                if existing is None:
                    self._db.execute(
                        "INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (canonical_id, normalized_identity.network_family, normalized_identity.network_identity, normalized_identity.asset_reference, symbol, name, decimals),
                    )
                for alias_type, value, source_id in prepared:
                    key = (normalized_identity.network_family, normalized_identity.network_identity, alias_type, value, source_id)
                    mapped = self._db.execute(
                        "SELECT canonical_id FROM aliases WHERE network_family=? AND network_identity=? AND alias_type=? AND alias_value=? AND source_id=?",
                        key,
                    ).fetchone()
                    if mapped is not None and mapped[0] != canonical_id:
                        raise AmbiguousAssetAliasError(f"{alias_type} alias is already bound in this scope")
                    self._db.execute(
                        "INSERT OR IGNORE INTO aliases VALUES (?, ?, ?, ?, ?, ?)",
                        (*key, canonical_id),
                    )
                self._db.execute("COMMIT")
                return record
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def add_alias(self, identity: AssetIdentity, alias: AssetAlias) -> None:
        identity.validate()
        alias_type, value, source_id = alias.normalized()
        canonical_id = identity.canonical_id
        key = (identity.network_family, identity.network_identity, alias_type, value, source_id)
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                exists = self._db.execute("SELECT 1 FROM assets WHERE canonical_id=?", (canonical_id,)).fetchone()
                if exists is None:
                    raise AssetNotFoundError("asset must be registered before aliases are added")
                mapped = self._db.execute(
                    "SELECT canonical_id FROM aliases WHERE network_family=? AND network_identity=? AND alias_type=? AND alias_value=? AND source_id=?",
                    key,
                ).fetchone()
                if mapped is not None and mapped[0] != canonical_id:
                    raise AmbiguousAssetAliasError(f"{alias_type} alias is already bound in this scope")
                self._db.execute("INSERT OR IGNORE INTO aliases VALUES (?, ?, ?, ?, ?, ?)", (*key, canonical_id))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def get(self, identity: AssetIdentity) -> AssetRecord:
        canonical_id = identity.canonical_id
        with self._lock:
            self._ensure_open()
            row = self._db.execute(
                "SELECT canonical_id, network_family, network_identity, asset_reference, symbol, name, decimals FROM assets WHERE canonical_id=?",
                (canonical_id,),
            ).fetchone()
            if row is None:
                raise AssetNotFoundError("canonical asset is not registered")
            return self._record(row)

    def resolve(self, *, network_family: Literal["evm", "solana"], network_identity: str, alias_type: Literal["symbol", "provider_id", "name"], value: str, source_id: str | None = None) -> AssetRecord:
        normalized = _normalize_alias(alias_type, value)
        if not isinstance(network_family, str) or network_family not in {"evm", "solana"}:
            raise AssetIdentityError("unsupported network_family")
        if not isinstance(network_identity, str) or not _NETWORK_ID.fullmatch(network_identity):
            raise AssetIdentityError("network_identity must be a lowercase SHA-256 fingerprint")
        if source_id is not None and (not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", source_id)):
            raise AssetIdentityError("source_id must be lowercase and URL-safe")
        if alias_type == "provider_id" and source_id is None:
            raise AssetIdentityError("provider_id resolution requires a source_id")
        with self._lock:
            self._ensure_open()
            keys = [source_id, ""] if source_id is not None else [""]
            for scope in keys:
                row = self._db.execute(
                    """SELECT a.canonical_id, a.network_family, a.network_identity,
                              a.asset_reference, a.symbol, a.name, a.decimals
                       FROM aliases x JOIN assets a ON a.canonical_id=x.canonical_id
                       WHERE x.network_family=? AND x.network_identity=?
                         AND x.alias_type=? AND x.alias_value=? AND x.source_id=?""",
                    (network_family, network_identity, alias_type, normalized, scope),
                ).fetchone()
                if row is not None:
                    return self._record(row)
        raise AssetNotFoundError("no asset matches this network-scoped alias")

    def list_assets(self, *, network_family: Literal["evm", "solana"] | None = None, network_identity: str | None = None) -> tuple[AssetRecord, ...]:
        if network_family is not None and (not isinstance(network_family, str) or network_family not in {"evm", "solana"}):
            raise AssetIdentityError("unsupported network_family")
        if network_identity is not None and (not isinstance(network_identity, str) or not _NETWORK_ID.fullmatch(network_identity)):
            raise AssetIdentityError("network_identity must be a lowercase SHA-256 fingerprint")
        query = "SELECT canonical_id, network_family, network_identity, asset_reference, symbol, name, decimals FROM assets"
        clauses = []
        params = []
        if network_family is not None:
            clauses.append("network_family=?")
            params.append(network_family)
        if network_identity is not None:
            clauses.append("network_identity=?")
            params.append(network_identity)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY canonical_id"
        with self._lock:
            self._ensure_open()
            rows = self._db.execute(query, params).fetchall()
            return tuple(self._record(row) for row in rows)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self) -> "AssetRegistry":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


__all__ = ["AmbiguousAssetAliasError", "AssetAlias", "AssetIdentity", "AssetIdentityError", "AssetNotFoundError", "AssetRecord", "AssetRegistry"]

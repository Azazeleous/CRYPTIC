"""Tests for network-scoped canonical asset identity and aliases."""
import unittest
from src.ingestion.asset_identity import (
    AmbiguousAssetAliasError, AssetAlias, AssetIdentity, AssetIdentityError,
    AssetNotFoundError, AssetRegistry,
)

NETWORK_A = "a" * 64
NETWORK_B = "b" * 64
EVM_A = AssetIdentity("evm", NETWORK_A, "0x" + "11" * 20)
EVM_B = AssetIdentity("evm", NETWORK_B, "0x" + "11" * 20)
EVM_C = AssetIdentity("evm", NETWORK_A, "0x" + "22" * 20)


class AssetIdentityTests(unittest.TestCase):
    def test_contract_address_case_normalizes_to_same_canonical_id(self):
        a = AssetIdentity("evm", NETWORK_A, "0x" + "ab" * 20)
        b = AssetIdentity("evm", NETWORK_A, "0x" + "AB" * 20)
        self.assertEqual(a.canonical_id, b.canonical_id)

    def test_same_contract_on_different_networks_is_distinct(self):
        self.assertNotEqual(EVM_A.canonical_id, EVM_B.canonical_id)

    def test_ticker_collision_on_one_network_is_rejected(self):
        registry = AssetRegistry()
        registry.register(EVM_A, symbol="USDC", name="USD Coin", decimals=6)
        with self.assertRaises(AmbiguousAssetAliasError):
            registry.register(EVM_C, symbol="USDC", name="USD Coin", decimals=6)

    def test_same_ticker_on_different_networks_resolves_in_scope(self):
        registry = AssetRegistry()
        registry.register(EVM_A, symbol="ETH")
        registry.register(EVM_B, symbol="ETH")
        self.assertEqual(registry.resolve(network_family="evm", network_identity=NETWORK_A, alias_type="symbol", value="eth").identity, EVM_A)
        self.assertEqual(registry.resolve(network_family="evm", network_identity=NETWORK_B, alias_type="symbol", value="ETH").identity, EVM_B)

    def test_provider_alias_overrides_global_symbol_for_that_source(self):
        registry = AssetRegistry()
        registry.register(EVM_A, symbol="ABC")
        registry.register(EVM_C)
        registry.add_alias(EVM_C, AssetAlias("symbol", "ABC", "provider-x"))
        resolved = registry.resolve(network_family="evm", network_identity=NETWORK_A, alias_type="symbol", value="ABC", source_id="provider-x")
        self.assertEqual(resolved.identity, EVM_C)

    def test_provider_ids_require_source_scope(self):
        with self.assertRaises(AssetIdentityError):
            AssetAlias("provider_id", "asset-42").normalized()
        with self.assertRaises(AssetIdentityError):
            AssetRegistry().resolve(network_family="evm", network_identity=NETWORK_A, alias_type="provider_id", value="asset-42")

    def test_alias_conflicts_are_rejected(self):
        registry = AssetRegistry()
        registry.register(EVM_A, symbol="AAA")
        registry.register(EVM_C, symbol="CCC")
        with self.assertRaises(AmbiguousAssetAliasError):
            registry.add_alias(EVM_C, AssetAlias("symbol", "AAA"))

    def test_unknown_alias_fails_closed(self):
        with self.assertRaises(AssetNotFoundError):
            AssetRegistry().resolve(network_family="evm", network_identity=NETWORK_A, alias_type="symbol", value="MISSING")

    def test_native_asset_is_explicit(self):
        self.assertTrue(AssetIdentity("solana", NETWORK_A, "native").canonical_id.endswith(":native"))

    def test_solana_mint_must_decode_to_32_bytes(self):
        AssetIdentity("solana", NETWORK_A, "So11111111111111111111111111111111111111112").validate()
        with self.assertRaises(AssetIdentityError):
            AssetIdentity("solana", NETWORK_A, "not-a-mint").validate()

    def test_normalized_chain_observation_is_required(self):
        identity = AssetIdentity.from_normalized_chain({"schema": "cryptic.normalized-chain-head.v1", "network_family": "evm", "network_identity": NETWORK_A}, "0x" + "44" * 20)
        self.assertEqual(identity.network_identity, NETWORK_A)
        with self.assertRaises(AssetIdentityError):
            AssetIdentity.from_normalized_chain({}, "native")

    def test_metadata_conflict_is_rejected(self):
        registry = AssetRegistry()
        registry.register(EVM_A, symbol="AAA", decimals=18)
        with self.assertRaises(AssetIdentityError):
            registry.register(EVM_A, symbol="AAA", decimals=6)

    def test_listing_is_deterministic_and_filterable(self):
        registry = AssetRegistry()
        registry.register(EVM_C, symbol="CCC")
        registry.register(EVM_A, symbol="AAA")
        registry.register(EVM_B, symbol="BBB")
        listed = registry.list_assets(network_family="evm", network_identity=NETWORK_A)
        self.assertEqual([item.identity for item in listed], [EVM_A, EVM_C])


if __name__ == "__main__":
    unittest.main()

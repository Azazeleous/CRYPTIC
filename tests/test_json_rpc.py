"""Protocol and contract tests for bounded read-only JSON-RPC adapters.

Live endpoint checks are opt-in through CRYPTIC_EVM_RPC_URL and
CRYPTIC_SOLANA_RPC_URL. No network simulator or fake provider is used.
"""
import json
import os
import unittest

from src.ingestion.json_rpc import (
    EvmReadOnlyAdapter,
    JsonRpcClient,
    JsonRpcError,
    JsonRpcPolicy,
    JsonRpcRemoteError,
    SolanaReadOnlyAdapter,
)
from src.ingestion.source_registry import SourceRegistryError


class JsonRpcProtocolTests(unittest.TestCase):
    def test_valid_result_envelope(self):
        payload = json.dumps({"jsonrpc": "2.0", "id": 17, "result": "0x1"}).encode()
        self.assertEqual(JsonRpcClient.parse_response(payload, 17, 1024), "0x1")

    def test_provider_error_is_structured(self):
        payload = json.dumps({
            "jsonrpc": "2.0", "id": 18,
            "error": {"code": -32601, "message": "Method not found"},
        }).encode()
        with self.assertRaises(JsonRpcRemoteError) as caught:
            JsonRpcClient.parse_response(payload, 18, 1024)
        self.assertEqual(caught.exception.code, -32601)

    def test_response_id_mismatch_fails_closed(self):
        payload = b'{"jsonrpc":"2.0","id":2,"result":1}'
        with self.assertRaisesRegex(JsonRpcError, "id_mismatch"):
            JsonRpcClient.parse_response(payload, 1, 1024)

    def test_response_cannot_contain_result_and_error(self):
        payload = b'{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":-1,"message":"x"}}'
        with self.assertRaisesRegex(JsonRpcError, "exactly_one"):
            JsonRpcClient.parse_response(payload, 1, 1024)

    def test_response_size_is_bounded(self):
        with self.assertRaisesRegex(JsonRpcError, "size_invalid"):
            JsonRpcClient.parse_response(b"x" * 129, 1, 128)

    def test_invalid_json_and_envelope_are_rejected(self):
        with self.assertRaisesRegex(JsonRpcError, "json_invalid"):
            JsonRpcClient.parse_response(b"{", 1, 1024)
        with self.assertRaisesRegex(JsonRpcError, "envelope_invalid"):
            JsonRpcClient.parse_response(b'{"id":1,"result":2}', 1, 1024)

    def test_endpoint_requires_tls_or_loopback_http(self):
        with self.assertRaisesRegex(SourceRegistryError, "HTTPS"):
            JsonRpcClient("http://rpc.example.org", allowed_methods=frozenset({"read"}))
        with self.assertRaisesRegex(SourceRegistryError, "credentials"):
            JsonRpcClient("https://user:pass@rpc.example.org", allowed_methods=frozenset({"read"}))

    def test_policy_bounds_are_enforced(self):
        with self.assertRaisesRegex(SourceRegistryError, "timeout_seconds"):
            JsonRpcPolicy(timeout_seconds=90).validate()
        with self.assertRaisesRegex(SourceRegistryError, "max_retries"):
            JsonRpcPolicy(max_retries=9).validate()

    def test_method_allowlist_blocks_state_changing_calls(self):
        with self.assertRaisesRegex(SourceRegistryError, "read-only methods"):
            JsonRpcClient(
                "https://rpc.example.org",
                allowed_methods=frozenset({"eth_sendRawTransaction"}),
            )
        client = JsonRpcClient(
            "https://rpc.example.org",
            allowed_methods=frozenset({"eth_chainId", "eth_blockNumber"}),
        )
        with self.assertRaisesRegex(JsonRpcError, "not_allowlisted"):
            client.call("eth_sendRawTransaction", ["0xdeadbeef"])
        with self.assertRaisesRegex(JsonRpcError, "not_allowlisted"):
            client.call("eth_sendTransaction", [{}])

    def test_evm_adapter_contract_and_quantity_parser(self):
        adapter = EvmReadOnlyAdapter("https://rpc.example.org")
        self.assertEqual(adapter.descriptor.schema_id, "cryptic.evm-chain-observation.v1")
        self.assertEqual(adapter._hex_quantity("0x539", "chain_id"), 1337)
        with self.assertRaisesRegex(JsonRpcError, "quantity_invalid"):
            adapter._hex_quantity("not-hex", "chain_id")
        with self.assertRaisesRegex(SourceRegistryError, "one unfiltered"):
            adapter.fetch_page(limit=2)

    def test_solana_adapter_contract(self):
        adapter = SolanaReadOnlyAdapter("https://rpc.example.org")
        self.assertEqual(adapter.descriptor.schema_id, "cryptic.solana-chain-observation.v1")
        self.assertEqual(adapter.client.allowed_methods, frozenset({
            "getGenesisHash", "getSlot", "getBlockHeight",
        }))
        with self.assertRaisesRegex(SourceRegistryError, "one unfiltered"):
            adapter.fetch_page(limit=1, filters={"address": "not-accepted-here"})

    def test_adapters_register_with_shared_registry(self):
        registry = __import__("src.ingestion.source_registry", fromlist=["SourceRegistry"]).SourceRegistry()
        registry.register(EvmReadOnlyAdapter("https://evm.example.org"))
        registry.register(SolanaReadOnlyAdapter("https://solana.example.org"))
        self.assertEqual(
            [item.source_id for item in registry.list_sources()],
            ["evm-rpc", "solana-rpc"],
        )


@unittest.skipUnless(os.environ.get("CRYPTIC_EVM_RPC_URL"), "set CRYPTIC_EVM_RPC_URL for live EVM RPC verification")
class LiveEvmRpcTests(unittest.TestCase):
    def test_live_chain_identity_and_head(self):
        adapter = EvmReadOnlyAdapter(os.environ["CRYPTIC_EVM_RPC_URL"])
        observation = adapter.observe()
        self.assertGreaterEqual(observation["chain_id"], 1)
        self.assertGreaterEqual(observation["block_number"], 0)


@unittest.skipUnless(os.environ.get("CRYPTIC_SOLANA_RPC_URL"), "set CRYPTIC_SOLANA_RPC_URL for live Solana RPC verification")
class LiveSolanaRpcTests(unittest.TestCase):
    def test_live_genesis_and_finalized_head(self):
        adapter = SolanaReadOnlyAdapter(os.environ["CRYPTIC_SOLANA_RPC_URL"])
        observation = adapter.observe()
        self.assertTrue(observation["genesis_hash"])
        self.assertGreaterEqual(observation["slot"], 0)
        self.assertGreaterEqual(observation["block_height"], 0)


if __name__ == "__main__":
    unittest.main()

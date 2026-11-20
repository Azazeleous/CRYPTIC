"""Tests for the isolated, prestarted DNS resolver."""
import ipaddress
import socket
import time
import unittest

from src.ingestion.dns_resolver import (
    DnsResolverDeadlineExceeded,
    DnsResolverError,
    IsolatedDnsResolver,
)


class IsolatedDnsResolverTests(unittest.TestCase):
    def test_resolves_localhost_in_supervised_process(self):
        with IsolatedDnsResolver() as resolver:
            addresses = resolver.resolve(
                "localhost", 443, deadline_monotonic=time.monotonic() + 5,
            )
            self.assertTrue(addresses)
            self.assertTrue(resolver.healthy)
            for family, address in addresses:
                self.assertIn(family, (socket.AF_INET, socket.AF_INET6))
                ipaddress.ip_address(address)

    def test_ip_literal_does_not_require_dns_round_trip(self):
        with IsolatedDnsResolver() as resolver:
            self.assertEqual(
                resolver.resolve(
                    "127.0.0.1", 443,
                    deadline_monotonic=time.monotonic() + 1,
                ),
                ((socket.AF_INET, "127.0.0.1"),),
            )

    def test_expired_deadline_fails_before_ipc(self):
        with IsolatedDnsResolver() as resolver:
            with self.assertRaises(DnsResolverDeadlineExceeded):
                resolver.resolve(
                    "localhost", 443,
                    deadline_monotonic=time.monotonic() - 1,
                )
            self.assertTrue(resolver.healthy)

    def test_expired_deadline_also_rejects_ip_literal_fast_path(self):
        with IsolatedDnsResolver() as resolver:
            with self.assertRaises(DnsResolverDeadlineExceeded):
                resolver.resolve(
                    "127.0.0.1", 443,
                    deadline_monotonic=time.monotonic() - 1,
                )

    def test_invalid_host_and_port_are_rejected(self):
        with IsolatedDnsResolver() as resolver:
            with self.assertRaisesRegex(DnsResolverError, "hostname_invalid"):
                resolver.resolve(
                    "", 443, deadline_monotonic=time.monotonic() + 1,
                )
            with self.assertRaisesRegex(DnsResolverError, "port_invalid"):
                resolver.resolve(
                    "localhost", 0, deadline_monotonic=time.monotonic() + 1,
                )

    def test_closed_resolver_cannot_be_reused(self):
        resolver = IsolatedDnsResolver()
        resolver.close()
        self.assertFalse(resolver.healthy)
        with self.assertRaisesRegex(DnsResolverError, "resolver_unavailable"):
            resolver.resolve(
                "localhost", 443,
                deadline_monotonic=time.monotonic() + 1,
            )


if __name__ == "__main__":
    unittest.main()

"""Contract tests for the read-only source registry."""
import unittest

from src.ingestion.source_registry import (
    HealthReport,
    SourceAdapterError,
    SourceDescriptor,
    SourcePage,
    SourceRegistry,
    SourceRegistryError,
)


class FakeAdapter:
    def __init__(self, descriptor=None, *, fail_health=False, page=None):
        self.descriptor = descriptor or SourceDescriptor(
            source_id="sample-api",
            source_kind="public_registry",
            endpoint="https://example.invalid/v1",
            auth_mode="none",
            rate_limit_per_minute=60,
            max_page_size=100,
            pagination_mode="cursor",
            schema_id="sample.record.v1",
        )
        self.fail_health = fail_health
        self.page = page

    def health_check(self):
        if self.fail_health:
            raise OSError("private connection detail must not escape")
        return HealthReport(self.descriptor.source_id, True, 1000, latency_ms=12)

    def fetch_page(self, *, limit, cursor=None, filters=None):
        if self.page is not None:
            return self.page
        return SourcePage(
            self.descriptor.source_id,
            self.descriptor.schema_id,
            1000,
            tuple({"id": str(i)} for i in range(min(limit, 2))),
            next_cursor="next-page",
        )


class SourceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = SourceRegistry()
        self.adapter = FakeAdapter()
        self.registry.register(self.adapter)

    def test_registration_and_deterministic_listing(self):
        other = FakeAdapter(SourceDescriptor(
            source_id="alpha-source",
            source_kind="local_file",
            endpoint="file:///var/tmp/source.jsonl",
            auth_mode="none",
            rate_limit_per_minute=1,
            max_page_size=10,
            pagination_mode="none",
            schema_id="local.record.v1",
        ))
        self.registry.register(other)
        self.assertEqual(
            [item.source_id for item in self.registry.list_sources()],
            ["alpha-source", "sample-api"],
        )

    def test_duplicate_source_id_is_rejected(self):
        with self.assertRaisesRegex(SourceRegistryError, "already registered"):
            self.registry.register(FakeAdapter())

    def test_write_capable_descriptor_is_rejected(self):
        descriptor = SourceDescriptor(
            source_id="unsafe-source",
            source_kind="public_registry",
            endpoint="https://example.invalid",
            auth_mode="none",
            rate_limit_per_minute=10,
            max_page_size=10,
            pagination_mode="none",
            schema_id="sample.v1",
            read_only=False,
        )
        with self.assertRaisesRegex(SourceRegistryError, "read-only"):
            self.registry.register(FakeAdapter(descriptor))

    def test_embedded_credentials_and_query_secrets_are_rejected(self):
        descriptor = SourceDescriptor(
            source_id="bad-source",
            source_kind="public_registry",
            endpoint="https://user:pass@example.invalid/data",
            auth_mode="none",
            rate_limit_per_minute=10,
            max_page_size=10,
            pagination_mode="none",
            schema_id="sample.v1",
        )
        with self.assertRaisesRegex(SourceRegistryError, "credentials"):
            descriptor.validate()

    def test_health_failure_is_sanitized(self):
        self.registry.register(FakeAdapter(fail_health=True), replace=True)
        report = self.registry.health_check("sample-api")
        self.assertFalse(report.healthy)
        self.assertEqual(report.reason, "adapter_health_check_failed")
        self.assertNotIn("private connection detail", report.reason)

    def test_page_size_is_bounded_before_adapter_call(self):
        with self.assertRaisesRegex(SourceRegistryError, "page-size"):
            self.registry.fetch_page("sample-api", limit=101)

    def test_page_is_checked_against_source_and_schema(self):
        page = self.registry.fetch_page("sample-api", limit=10)
        self.assertEqual(page.source_id, "sample-api")
        self.assertLessEqual(len(page.items), 10)

        bad = SourcePage("other-source", "sample.record.v1", 1000, ())
        self.registry.register(FakeAdapter(page=bad), replace=True)
        with self.assertRaisesRegex(SourceAdapterError, "source_id"):
            self.registry.fetch_page("sample-api", limit=10)

    def test_credential_like_filter_fields_are_rejected(self):
        with self.assertRaisesRegex(SourceRegistryError, "credential"):
            self.registry.fetch_page(
                "sample-api", limit=10, filters={"access_token": "should-not-be-here"}
            )

    def test_offset_pagination_is_bounded(self):
        descriptor = SourceDescriptor(
            source_id="offset-api",
            source_kind="public_registry",
            endpoint="https://example.invalid/list",
            auth_mode="none",
            rate_limit_per_minute=30,
            max_page_size=20,
            pagination_mode="offset",
            schema_id="offset.record.v1",
        )
        registry = SourceRegistry()
        registry.register(FakeAdapter(descriptor))
        with self.assertRaisesRegex(SourceRegistryError, "offset cursor"):
            registry.fetch_page("offset-api", limit=5, cursor="-1")

    def test_unregister_is_explicit(self):
        self.assertTrue(self.registry.unregister("sample-api"))
        self.assertFalse(self.registry.unregister("sample-api"))
        with self.assertRaisesRegex(SourceRegistryError, "not registered"):
            self.registry.get_descriptor("sample-api")


if __name__ == "__main__":
    unittest.main()

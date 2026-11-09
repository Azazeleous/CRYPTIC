# Extension Absorption

An extension is a package of inspectable capability, not an automatic privilege grant.

Manifest fields: extension_id, version, description, license, source_uri, source_digest, entrypoints, runtime, dependencies, declared_capabilities, permissions, resource_limits, data_handling, tests, provenance.

Lifecycle:
1. Discover source.
2. Record origin, license, digest, and revision.
3. Inspect code, dependencies, and declared behavior.
4. Generate an interface summary and threat assessment.
5. Resolve dependencies in an isolated build.
6. Run static analysis and sandbox tests.
7. Run conformance and regression suites.
8. Review requested permissions.
9. Register only approved capabilities.
10. Monitor, update, disable, or revoke.

The model may learn an extension's interface and implementation patterns without importing its secrets, executing untrusted code in the host, or inheriting its privileges.

# Storage Design

Use content-addressed immutable objects plus explicit manifests and indexes. Separate payload bytes from metadata and references.

## Stream and chunk model
- Accept bounded input streams and apply backpressure.
- Encode text with a declared character encoding before binary conversion; retain original bytes and encoding metadata.
- Chunk by configured byte size, not character count.
- Proposed target: 8 MiB logical segment composed of four 2 MiB streams. Treat this as a testable layout parameter, not a fixed hardware constraint.
- Store chunk digest, byte length, sequence, compression codec, encryption metadata, and parent manifest.
- Verify each chunk on write and read; verify whole-object digest after reassembly.
- Use sparse files/bundles only where the target filesystem supports and documents their semantics.
- Keep source links in a signed manifest/index, not duplicated data URLs inside every chunk.
- Do not assume a fixed 388 KiB remainder; measure actual filesystem, metadata, alignment, and bundle overhead.

## Recovery
Rebuild from manifests, validate chunk hashes, detect missing/corrupt chunks, repair from verified replicas, and record recovery provenance.

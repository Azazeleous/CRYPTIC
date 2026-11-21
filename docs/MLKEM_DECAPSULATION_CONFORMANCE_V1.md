# ML-KEM Decapsulation Conformance — v1

- Status: specification and test-plan addition; provider implementation and ACVP execution pending
- Standard: NIST FIPS 203, ML-KEM
- ACVP operation: `ML-KEM / encapDecap / VAL / decapsulation`
- FIPS algorithm: Algorithm 18, ML-KEM.Decaps_internal
- Registry operation: `KEM_DECAPSULATE`
- Scope: ML-KEM-768 initially; parameter-set expansion only when explicitly enabled and tested

## 1. Operation semantics

`KEM_DECAPSULATE` is a key-encapsulation/key-establishment operation. It accepts an ML-KEM decapsulation key and ciphertext and returns a 32-byte shared secret. It does not return application plaintext and must not be mislabeled as generic `DECRYPT`.

The internal algorithm decrypts the K-PKE ciphertext to recover a candidate message, derives a candidate shared secret and re-encryption randomness, re-encrypts, and compares the reconstructed ciphertext with the supplied ciphertext. A mismatch selects the implicit-rejection shared secret derived from the decapsulation key's rejection value and the supplied ciphertext.

The internal path-selection/implicit-reject flag is secret intermediate state. It must not be returned, logged, exported in telemetry, or exposed through distinct application-visible error behavior.

## 2. Input-validation boundary

Keep key/ciphertext structural validation separate from implicit rejection:

- Validate the public API input types and exact required lengths before entering the internal decapsulation algorithm.
- Validate the decapsulation key structure and the embedded public-key hash relationship as required by FIPS 203 §7.3.
- A malformed or wrong-length input is an input-validation failure.
- A correctly sized, modified ciphertext is processed through the implicit-rejection path and returns a 32-byte shared secret.
- Do not convert a malformed-key failure into a successful implicit-rejection result.
- Do not create a distinguishable application response for the internal valid-versus-implicit-rejection path.

## 3. ACVP test matrix

For every supported parameter set and vector revision, consume the official ACVP test groups and compare outputs exactly.

| Case | ACVP type | Input condition | Expected behavior | Acceptance |
|---|---|---|---|---|
| DCP-01 | VAL | Valid decapsulation key + original ciphertext | Ordinary decapsulation | Returned 32-byte shared secret equals vector output byte-for-byte |
| DCP-02 | VAL | Valid decapsulation key + modified, correctly sized ciphertext | Implicit rejection | Returned 32-byte shared secret equals vector output byte-for-byte |
| DCP-03 | VAL | Valid decapsulation key check | Key check succeeds | Expected validation result |
| DCP-04 | VAL | Decapsulation key with modified embedded hash | Key check fails | Expected validation result |
| DCP-05 | Supplemental | Wrong-length ciphertext | Reject at input boundary | Stable documented input-validation result; not an ACVP implicit-rejection pass |
| DCP-06 | Supplemental | Wrong-length or malformed decapsulation key | Reject at input boundary | Stable documented input-validation result |
| DCP-07 | Supplemental | Repeated valid/modified ciphertext trials | No path flag or secret leakage | API-visible outputs contain only the shared secret or documented structural-input error |

ACVP VAL decapsulation vectors include valid and modified-ciphertext cases. The ACVP server supplies the decapsulation key and ciphertext; the implementation returns the expected shared secret for either path. The modified-ciphertext case is not passed by returning an error: the expected result is the implicit-rejection shared secret.

## 4. Provider contract

The provider adapter exposes a typed method equivalent to:

```text
decapsulate(parameter_set, decapsulation_key, ciphertext) -> shared_secret[32]
```

Contract requirements:

- No random input is required by FIPS 203 decapsulation.
- The provider must not substitute a custom KEM, custom hash, prime-derived secret, or application-specific fallback.
- The test harness must not infer correctness from a round trip alone; compare each returned shared secret against the official vector output.
- A missing provider method is `UNSUPPORTED`, never a pass.
- Provider identity, version, build, platform, parameter set, vector revision, and vector-set digest are recorded in the run manifest.
- Secret key bytes, shared secrets, rejection values, and internal flags are excluded from ordinary logs.

## 5. FIPS 140-3 module evidence

For a module claiming support for ML-KEM, prepare conditional algorithm self-test evidence for the supported ML-KEM functions. Decapsulation self-test coverage must include both the ordinary/non-rejection and implicit-rejection paths under the applicable CMVP Implementation Guidance.

Record:
- module name, version, build, operational environment, and configuration;
- algorithm and parameter set;
- self-test vector-set identifier and digest;
- execution time and pass/fail result;
- evidence artifact reference and integrity digest;
- failure handling and module state transition.

This repository test plan is not a CMVP certificate and does not claim formal validation. ACVP algorithm validation and FIPS 140-3 module validation remain separate formal processes.

## 6. Operation registry

The registry distinguishes payload decryption from KEM key establishment:

| Operation ID | Family | Purpose | Result |
|---|---|---|---|
| `AEAD_DECRYPT` | Authenticated encryption | Recover application plaintext after authenticated decryption | Plaintext or authentication failure |
| `KEM_DECAPSULATE` | Key encapsulation | Derive the shared secret corresponding to a KEM ciphertext | 32-byte shared secret |

A later protocol layer may feed the KEM shared secret into a separately specified KDF and authenticated-encryption scheme. That protocol must be independently specified and tested; it is not part of ML-KEM decapsulation itself.

## 7. Acceptance gates

1. Schema-check the pinned official ACVP vector files and record their content digests.
2. Demonstrate byte-exact valid decapsulation results.
3. Demonstrate byte-exact implicit-rejection results for modified, correctly sized ciphertexts.
4. Demonstrate the encapsulation-key and decapsulation-key validation cases required by the selected ACVP revision.
5. Demonstrate supplemental malformed-input behavior without confusing it with implicit rejection.
6. Demonstrate no exposed internal reject flag and no secret-bearing logs.
7. Demonstrate module self-test coverage for both decapsulation paths.
8. Only after all local required cases pass, proceed to formal ACVP/CAVP work with an accredited CST laboratory; pursue CMVP separately for the complete cryptographic module.

## 8. References

- NIST FIPS 203, Sections 3.2, 3.3, 6.3, and 7.3; Algorithm 18.
- NIST ACVP ML-KEM specification, test types and encapDecap VAL schema.
- Applicable NIST CMVP Implementation Guidance for FIPS 140-3 ML-KEM self-tests.

## 9. Governing invariants

- Boundary — Nothing executes beyond its time.
- Capacity — Nothing claims capacity without measurement.
- Correctness — Nothing claims correctness without verification.

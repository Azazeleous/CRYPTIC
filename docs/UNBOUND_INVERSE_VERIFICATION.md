# AE.MINERVA.UNBOUND.INVERSE/1

The module accepts injected forward and inverse operators with compatible
domains and codomains. For a target Y, it computes X = F^-1(Y), then computes
Y_check = F(X). It accepts only when Y_check equals Y under the supplied
equality predicate.

A separate left-inverse check verifies F^-1(F(X)) = X for a supplied domain
value. Checking both identities over a finite domain is stronger than checking
one target, but does not establish behavior outside that domain.

The HCCGN verifier uses this module for primary and compact modular stride
projections. Inverse evidence is returned by the verifier without changing
HCCGN proof bytes or claiming SHA-256 inversion.

Modular inverse reconstruction applies to the coprime stride transform.
SHA-256 round inversion requires the round constant and message-schedule word;
the digest alone does not provide those values. A verified modular or
round-level inverse is not a general SHA-256 preimage attack.

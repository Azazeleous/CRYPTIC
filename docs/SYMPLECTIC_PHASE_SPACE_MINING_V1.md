# CRYPTIC Symplectic Phase-Space & Mining System V1

## Purpose and boundary

This module adds two mathematically distinct symplectic engines and uses the
finite one as a deterministic ordering permutation for bounded HCCGN mining
windows. It does not invert SHA-256, change the HCCGN-WORK/1 preimage, change
the active target, reduce the assigned search interval, or alter consensus.

## Continuous Hamiltonian phase-space engine

For a separable Hamiltonian

\[
H(q,p)=V(q)+\sum_i \frac{p_i^2}{2m_i},
\]

the engine applies the kick-drift-kick Störmer-Verlet step:

\[
p_{n+1/2}=p_n-\frac{h}{2}\nabla V(q_n)
\]
\[
q_{n+1}=q_n+hM^{-1}p_{n+1/2}
\]
\[
p_{n+1}=p_{n+1/2}-\frac{h}{2}\nabla V(q_{n+1}).
\]

For a differentiable separable Hamiltonian this map is symplectic and
time-reversible under the corresponding negative step. It is not exactly
energy-conserving at each step; bounded-step trajectory tests measure energy
error rather than claiming exact conservation. Potential and gradient are
injected together, dimensions must agree, masses must be positive, and the
integrator enforces a finite step budget.

## Exact finite phase-space map

Mining uses a discrete canonical pair \((q,p)\in\mathbb Z_m^2\). The update is
the composition of two modular shears:

\[
p'=(p+kq)\bmod m,\qquad q'=(q+sp')\bmod m.
\]

Its matrix is

\[
M=\begin{bmatrix}1+sk&s\\k&1\end{bmatrix},\qquad \det(M)=1,
\]

so it preserves the canonical two-form modulo \(m\) and is bijective. Its
inverse is

\[
q=(q'-sp')\bmod m,\qquad p=(p'-kq)\bmod m.
\]

The signed HCCGN job already binds the primary and compact stride values;
these provide the deterministic drift and kick coefficients. The finite
candidate window has size \(N\), and the engine chooses
\(m=\max(2,\lceil\sqrt N\rceil)\). It permutes all \(m^2\) phase-space points
and retains mapped ordinals below \(N\). Since the map is a bijection, the
retained output is exactly the set \(\{0,\ldots,N-1\}\), once each, including
for non-square windows.

## Pool integration

The pool worker selects symplectic-phase-space-v1 for the signed half-open
nonce interval [nonce_start, nonce_start + max_attempts). The worker adds
each scheduled ordinal to nonce_start. The independent admission path
recomputes the HCCGN proof and rejects any proof nonce outside that exact
signed interval. Worker-reported schedule and timing measurements are
telemetry only and are not trusted for acceptance.

The HCCGN miner retains sequential-v1 as its direct-call default; callers
must explicitly request the symplectic schedule. The pool worker opts into it
as a fixed implementation profile. No pool-job wire fields or HCCGN proof
fields are added for this scheduling-only change.

## Verification

Tests cover modular inverse and full finite-lattice bijection, preservation of
the discrete canonical two-form, exact finite-window coverage for square and
non-square sizes, Störmer-Verlet reversibility and harmonic-oscillator area
preservation, bounded energy error, HCCGN proof verification after symplectic
nonce selection, and rejection of out-of-window pool proofs.

## Performance claim

This is a correctness-first traversal permutation, not a hash-rate accelerator.
The partial-tile filter adds bounded scheduling work. Performance must be
measured against sequential traversal on the same hardware, job, target, and
attempt count before any throughput claim is made.


## Remaining API integration

The HCCGN core miner exposes the schedule_profile argument and the pool worker selects the symplectic profile. The broader UnifiedMiningEngine wrapper is not yet wired to surface that optional selector; its HCCGN route therefore remains sequential by default. Exposing the selector through that wrapper is a follow-up integration, not a claim of completion in this change set. The generic Hamiltonian API also requires a caller-supplied separable potential, gradient, and masses; no project-specific physical Hamiltonian was present in the source specification.

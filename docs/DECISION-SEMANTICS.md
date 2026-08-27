# Decision semantics

The evaluator is deterministic. Given the same inputs, trust store, evidence bytes, candidate digest, and evaluation time, it returns the same result.

## PASS

All required evidence is present and matches its digest; the signed receipt binds the complete evidence set and exact candidate; the verifier is receiver-trusted and independent under policy; the signed authorization binds that receipt and candidate; and all standing is current.

## HOLD

A required precondition is incomplete or stale but no integrity violation or negative decision has been established. Examples include missing evidence, missing signature, missing receipt, future issue time within an unresolved state, or expired standing.

## BLOCK

An explicit negative outcome, integrity failure, or trust-boundary violation exists. Examples include candidate drift, digest mismatch, invalid or untrusted signature, owner collision, out-of-scope authorization, verifier `BLOCK`, authority `DENY`, or key revocation.

Precedence is `BLOCK` over `HOLD` over `PASS`. Multiple reasons are retained and sorted by stable code so an operator sees the complete decision.

## Historical and current standing

Offline verification reproduces the recorded decision using the dossier's stored receiver context and separately evaluates current standing using a caller-supplied candidate and complete protected receiver context. Missing current context is `BLOCK`; it never falls back to dossier-controlled values. A historically valid `PASS` can therefore remain intact while current status becomes `HOLD` after authorization expiry or `BLOCK` after key revocation, missing context, or receiver-context change.

The recorded time and dossier digest are explicitly `UNANCHORED`. Reproduction proves internal consistency, not an external historical timestamp. External historical proof requires a separately trusted signature, transparency log, or timestamp anchor.

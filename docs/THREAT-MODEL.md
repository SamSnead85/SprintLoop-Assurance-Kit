# Threat model

## Scope

SprintLoop Assurance Kit evaluates a candidate manifest, local deterministic evidence, an independently signed verifier receipt, a finite signed authorization, a receiver-owned policy, and a receiver-owned public-key trust store. It emits a decision and portable dossier.

It does not secure the systems that create those inputs. The caller must authenticate principals, protect private keys, preserve logs and evidence, and enforce the resulting status at the deployment boundary.

## Protected assets

- Exact candidate, intent, manifest, evidence-set, receipt, policy, and authorization bindings
- Verifier and authority identity, ownership, role, standing, expiry, and revocation
- Receiver-owned trust roots
- Decision history and dossier integrity
- Confidential evidence embedded in exported dossiers

## Trust boundaries

1. Builder and self-QA to evidence collector
2. Evidence collector to independent verifier
3. Verifier signing key to receiver-owned trust store
4. Verifier to named release authority
5. Authority signing key to receiver-owned trust store
6. Assurance decision to SCM/deployment interlock
7. Dossier producer to offline verifier

## Priority threats

| Threat | Failure | Control |
| --- | --- | --- |
| Candidate substitution | A prior pass is attached to new bytes | Every evidence item, receipt, authorization, and runtime invocation binds the exact Git digest |
| Candidate self-reference | A tracked manifest claims the commit/tree that contains it | Seal candidate first; retrieve manifest, receipt, authorization, and evidence out of band into a separate runner directory; prohibit candidate fallback |
| Provider ambiguity or downgrade | A mutable locator returns stale or attacker-selected proof | Authenticated receiver-governed lookup by the full exact-candidate coordinate; no `latest`, fallback, overwrite, or partial success |
| Evidence tampering | Artifact changes after verification | SHA-256 file verification and signed complete evidence-set binding |
| Receipt forgery | Untrusted producer invents a verifier | Ed25519 verification against receiver-owned key roles and identity metadata |
| Self-verification | Builder approves its own work | Policy-enforced principal, owner, or control-domain separation |
| Cosmetic independence | Same owner invokes another model | Model name is ignored for separation; stable owner and principal identifiers are authoritative |
| Authorization replay | Approval is reused outside scope or time | Candidate, manifest, receipt, environment, operation, issuance, and expiry bindings |
| Missing-proof promotion | Absent or stale inputs appear green | Missing external bundle/receiver context fails the integration or `BLOCK`s; incomplete eligibility evidence becomes `HOLD`; malformed or contradictory security inputs become `BLOCK` |
| Key compromise | Stolen signer produces valid signatures | Receiver-managed validity windows and revocation; production HSM/KMS and rotation required |
| Trust-store substitution | Attacker supplies its own public key | Trust store must come from a protected receiver boundary, never from the dossier |
| Policy substitution | Candidate weakens required controls | Canonical policy and trust-store digests are receiver-owned inputs and signed into receipt and authorization |
| Cross-context replay | Valid record is reused in another repository or environment | External repository/environment expectations and exact authorization scope |
| Head/tree drift | Evaluated files differ from the requested Git object | Direct Git HEAD/tree resolution and clean tracked-tree check at evaluation |
| Path traversal or symlink escape | Manifest reads arbitrary local files | Relative-path validation, real-path containment, regular-file and size checks |
| Dossier disclosure | Embedded evidence leaks sensitive data | Digest-only default, opt-in embedding, classification and retention controls |
| Stored-context replay | A dossier's historical context is reused as current receiver intent | Recorded reproduction may use stored context; current standing requires an external candidate and complete receiver context or returns `BLOCK` |
| Historical rewrite | Recorded decision is changed | Canonical input/dossier digests and reproducible recorded evaluation |
| Algorithm confusion | Signer selects a weak algorithm | v1 accepts Ed25519 only |
| Denial of service | Oversized JSON or evidence exhausts memory | Bounded descriptor reads, item count, per-artifact and aggregate byte limits |
| False historical certainty | Local clock/digest is treated as trusted timestamp | Dossiers are labeled `UNANCHORED`; external signature/timestamp required |

## Known limitations

- Canonical JSON is the kit's documented restricted profile, not a complete RFC 8785 implementation. Signed schemas permit safe integers only.
- The kit reads each evidence artifact into memory after enforcing its configured size limit.
- Git object integrity is provided by the caller's Git implementation; the kit binds the supplied canonical Git digest.
- A valid dossier is evidence of the configured evaluation, not proof that the software has no vulnerabilities.
- Local clock correctness is an operator responsibility.

## Production checklist

- Protect the policy and trust store with code review and branch rules.
- Keep verifier ownership separate from builder ownership in identity governance, not only configuration.
- Store private keys in a KMS/HSM or workload-identity signing service.
- Pin this Action and all upstream actions to reviewed immutable commits.
- Keep candidate checkout, protected policy/trust checkout, provider inbox, materialized bundle, and dossier output in separate trust locations.
- Authenticate the provider transport independently; the included materializer intentionally performs no fetch or credential handling.
- Configure the assurance job as a required status check tied to the expected GitHub App/Action source.
- Exercise revocation, expiry, recovery, and candidate-drift scenarios before enforcement.
- Export digest-only dossiers by default; explicitly approve embedded evidence.
- Obtain security and legal review appropriate to the deployment's risk.

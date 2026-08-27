# Model neutrality

SprintLoop Assurance Kit does not need an AI model to make its authoritative decision.

Deterministic controls verify candidate identity, evidence digests, signature validity, trust roles, ownership separation, policy obligations, scope, time, expiry, and revocation. Those controls remain authoritative even when a verifier uses a model.

## Acceptable model role

A model may produce evidence such as:

- semantic review findings;
- intent-to-change traceability suggestions;
- risk classification recommendations;
- control mappings;
- suspicious-change triage; or
- a summarized rationale for human review.

The independently owned verifier decides whether to sign a receipt after applying its deterministic checks and approved method. The release authority remains a separately identified principal.

## What a model cannot do

- Model metadata cannot prove identity or ownership.
- A different model under the builder's owner does not create independence.
- A model finding cannot override a digest, signature, expiry, scope, or separation failure.
- A model cannot grant its own trust standing.
- A model cannot sign as the named human authority.

## Custom-model decision

Do not train a custom model solely to make the product appear AI-native. First collect consented, de-identified pilot data and identify a repeated classification task with a measurable baseline. A useful future small model could normalize heterogeneous findings into the public control taxonomy or prioritize verifier review. It should remain replaceable, versioned in receipt metadata, independently evaluated, and non-authoritative.

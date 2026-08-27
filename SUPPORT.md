# Support

Community support for SprintLoop Assurance Kit is public and best effort. It is intended to make the open protocol usable and inspectable; it is not an operational SLA, compliance opinion, or review of a consuming organization's private control environment.

## Choose the right route

| Need | Route |
| --- | --- |
| Usage question or protocol discussion | [GitHub Discussions](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/discussions) |
| Reproducible non-security defect | [Bug report](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/issues/new?template=bug-report.yml) |
| Help placing the Kit in a public-safe workflow | [Integration help](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/issues/new?template=integration-help.yml) |
| Interoperable capability or protocol change | [Feature proposal](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/issues/new?template=feature-request.yml) |
| Measured shadow-pilot outcome | [Pilot field report](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/issues/new?template=pilot-field-report.yml) |
| Vulnerability, leaked secret, bypass, or unsafe default | [Private vulnerability report](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/security/advisories/new) |
| Sensitive conduct report | Follow the private route in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and prefix the title `CONDUCT:` |

Do not open a public issue for a suspected vulnerability. Do not paste customer data, source code from a private repository, credentials, keys, tokens, internal hostnames, absolute local paths, regulated evidence, or proprietary logs into any public route.

## A supportable report

Include only public-safe material:

- the tagged Kit version or full source commit;
- operating system, Node version, Git version, and integration surface;
- the exact command with secrets and private paths replaced by inert placeholders;
- expected result, actual disposition, exit code, and stable reason or error codes;
- a minimal reproduction using synthetic fixtures; and
- whether the issue disappears at the latest tagged minor release.

For `v0.3` and later, path-free JSON doctor output is useful when the setup doctor itself completed safely. Review it before posting. A doctor result is setup evidence, not a verifier receipt or release approval.

Maintainers may close reports that cannot be reproduced without private material, ask for a synthetic reproduction, or move a design question to Discussions. Never send a private key or active credential to a maintainer.

## Supported versions

Before `1.0`, only the latest tagged minor release receives security fixes. Development branches and untagged commits are available for review and testing but are not supported releases. Pin production-sensitive evaluation to a reviewed full commit and verify published checksums; do not depend on a moving branch or mutable tag.

## Response expectations

The community target is a first public triage response within two business days, measured as a project outcome rather than promised as an SLA. Security-report acknowledgement follows [SECURITY.md](SECURITY.md). Complex trust-boundary or protocol changes may require a public design issue, threat-model work, adversarial fixtures, and a later release.

## Boundary of help

Maintainers can explain documented behavior, reproduce public fixtures, identify a reason code, and review an interoperable change. Maintainers cannot certify that a private deployment is secure or compliant, accept custody of signing material, attest to a customer's evidence, or make a release decision for a consuming organization.

The local MCP server and shadow provider remain advisory even when support helps configure them. A managed SprintLoop deployment or operated pilot is a separate commercial service with a separate scope; the public protocol and exported dossier remain independently inspectable. See [docs/COMMERCIAL-BOUNDARY.md](docs/COMMERCIAL-BOUNDARY.md).

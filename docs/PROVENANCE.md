# Source and release provenance

The kit has no runtime or development package dependencies in version 0.1.0. It uses Node.js standard-library cryptography, file, process, and test APIs.

The complete clean-room provenance boundary is recorded in [SOURCE-INVENTORY.md](SOURCE-INVENTORY.md).

Repository gates generate an SPDX 2.3 SBOM from the package lock, scan source and fixtures for common credential and personal-data patterns, run adversarial tests, inspect the npm package contents, and calculate the packed artifact's SHA-256 subject.

The manual release-candidate workflow requires a clean full Git source revision and deliberately does not publish to npm, GitHub Releases, a container registry, or an attestation service. The package is `private:true`; its npm-format tarball is installation-tested only. A release owner must separately review the source revision, package inventory, SBOM, release subject, `SHA256SUMS`, license, and GitHub destination before enabling publication.

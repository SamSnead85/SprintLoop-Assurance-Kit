# Real-producer evidence collector corpus

This offline corpus checks structural interoperability between the evidence collector and artifacts emitted by real CI/security producers. It is not a claim-verification suite: every descriptor intentionally reports `claimsVerified: false`, and the collector does not verify test truth, scanner findings, SBOM completeness, provenance signatures, or Sigstore trust.

`expected-collection.json` pins the exact raw-byte digest, size, privacy-minimized summary, inspection level, and media metadata returned for every collector input. The test uses explicit declared formats, validates the complete result against the public evidence-collection schema, and compares it to that golden file.

## Verified lanes

| Lane | Corpus artifact | Producer/source | Immutable provenance | Public-safe treatment |
| --- | --- | --- | --- | --- |
| JUnit XML | `producer-output/pytest-9.0.2-junit.xml` | pytest 9.0.2 run against `inputs/pytest/test_example.py` | `python3 -m pytest --version` returned `pytest 9.0.2`; the checked-in input produced one pass, one intentional failure, and one skip | Normalized only elapsed times, run timestamp, hostname, and the absolute checkout prefix. Test structure and producer text are unchanged. |
| SARIF 2.1.0 | `producer-output/github-codeql-action-6f530319-sarif-2.1.0.json` | GitHub CodeQL Action test corpus, `src/testdata/fingerprinting.input.sarif` | Byte-for-byte copy from commit [`6f530319d8c989665d0835536ec9571735fd2008e`](https://github.com/github/codeql-action/blob/6f530319d8c989665d0835536ec9571735fd2008e/src/testdata/fingerprinting.input.sarif); fixture SHA-256 `a2ff9377fb1291b96045fdd830ec33712dba4729a2ea4df12121772de8626188` | No transformation. The source uses public placeholder filenames. Copyright GitHub; MIT notice is in `licenses/github-codeql-action-MIT.txt`. |
| SPDX 2.3 JSON | `producer-output/syft-1.31.0-spdx.json` | Anchore Syft 1.31.0 scanning `inputs/syft`; npm 10.9.8 generated the lockfile for the public `left-pad` 1.3.0 dependency | Official release binary Git commit `ab9db0024ed35ab6a4e33e539593f5a3c58a5594`; downloaded Darwin arm64 archive SHA-256 `f898fa53f2ea404d1a5ae7e28f75b5fc51a9fd234b99f593c9e7457464d931ef` matched the [v1.31.0 checksum file](https://github.com/anchore/syft/releases/tag/v1.31.0) | Normalized only the random document-namespace UUID and creation timestamp. The output declares `CC0-1.0` as its data license; Syft is Apache-2.0. |
| CycloneDX 1.6 JSON | `producer-output/syft-1.31.0-cyclonedx.json` | Anchore Syft 1.31.0 scanning the same lockfile-backed input | Same checksum-verified Syft binary as the SPDX lane | Normalized only the random serial UUID, generated root `bom-ref`, timestamp, and absolute source-file name (made corpus-relative). Producer/tool, package, component, license, PURL, CPE, and hash structure are unchanged. |
| in-toto/SLSA v1 | `producer-output/github-cli-attestation-21158102-slsa-v1.json` | GitHub-hosted `cli/cli` artifact attestation [#21158102](https://github.com/cli/cli/attestations/21158102), created by GitHub Actions | Downloaded public DSSE/Sigstore bundle SHA-256 `94da5cc2528f72c73f60268f2fff5009098701c02a5c8d832155e2888f016429` | Byte-for-byte base64-decoded DSSE payload; nothing inside the statement was rewritten. This lane proves statement parsing, not signature verification. |
| GitHub artifact-attestation bundle | `producer-output/github-cli-attestation-21158102-sigstore-bundle.json` | The same GitHub attestation download | Byte-for-byte public download; SHA-256 `94da5cc2528f72c73f60268f2fff5009098701c02a5c8d832155e2888f016429` | No transformation. Its certificate has an empty subject and a workflow-only SAN for `cli/cli`; no person or account identity is embedded. This lane proves bundle-envelope parsing, not trust verification. |
| Cosign Sigstore bundle v0.3 | `producer-output/cosign-3.1.3-sigstore-bundle.json` | Cosign 3.1.3 signing `inputs/cosign/subject.txt` with a temporary local ECDSA key | Official binary SHA-256 `5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76` matched the [v3.1.3 checksum file](https://github.com/sigstore/cosign/releases/tag/v3.1.3); Git commit `11926fa5bbbbde47e88fc006b625a17769b743b2` | Generated with transparency-log upload disabled, then verified with Cosign against `producer-output/cosign-3.1.3-public-key.pub`. The temporary private key was deleted. No identity certificate, account, repository name, timestamp, or secret is embedded. Cosign is Apache-2.0. |

There are no invented fallbacks or synthetic stand-ins for a missing producer. All six collector formats have a source-verified producer lane; Sigstore has independent GitHub-hosted and local-key Cosign lanes.

## Reproduction notes

The checked-in corpus is intentionally offline and does not download or execute producer tools during tests. Refreshes must pin and checksum the producer first, regenerate from the checked-in input (or copy an immutable upstream artifact), document every transformation, run the collector/schema golden test, verify any signature before destroying its private key, and run the repository sensitive-data scan.

Representative producer commands:

```sh
python3 -m pytest fixtures/collector-producers/inputs/pytest/test_example.py \
  --junitxml=fixtures/collector-producers/producer-output/pytest-9.0.2-junit.xml -q

syft scan dir:fixtures/collector-producers/inputs/syft \
  -o spdx-json=fixtures/collector-producers/producer-output/syft-1.31.0-spdx.json \
  -o cyclonedx-json=fixtures/collector-producers/producer-output/syft-1.31.0-cyclonedx.json

cosign sign-blob --key TEMPORARY_PRIVATE_KEY \
  --bundle fixtures/collector-producers/producer-output/cosign-3.1.3-sigstore-bundle.json \
  --use-signing-config=false --tlog-upload=false --yes \
  fixtures/collector-producers/inputs/cosign/subject.txt
```

The pytest command is expected to exit `1` because the input includes one deliberate failing test. Volatile-field normalization must be reviewed field by field; it must never be used to repair malformed producer structure or fabricate compatibility.

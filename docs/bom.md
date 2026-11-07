# SBOM and CBOM

This repository publishes two CycloneDX 1.6 documents:

| File | Contents |
| --- | --- |
| `sbom/sbom.cdx.json` | Software Bill of Materials for the npm dependency graph, generated from `package-lock.json`. |
| `sbom/cbom.cdx.json` | Cryptography Bill of Materials: every algorithm, protocol and piece of key material this package uses, with source evidence. |
| `sbom/crypto-inventory.json` | The reviewed input that drives the CBOM. Copied into published artifacts. |
| `sbom/SHA256SUMS` | Checksums for the published files. |

Both documents are committed. Regenerate them with `npm run bom` and commit
`sbom/` together with any dependency, source or crypto inventory change.

## Generate locally

Use the Node.js and npm versions the project supports and CI uses (Node.js 22
with npm 10). `@cyclonedx/cyclonedx-npm` invokes `npm ls --long`, which newer
npm major versions can change in incompatible ways.

```bash
npm run bom
```

The command:

1. runs `@cyclonedx/cyclonedx-npm` in lock-file-only mode and validates the
   resulting SBOM;
2. builds the CBOM from `crypto-inventory.json`;
3. adds deterministic provenance metadata (commit, lock-file hash, inventory
   hash, timestamp);
4. validates the CycloneDX structure and the dependency graph.

Individual steps are available as `npm run bom:sbom`, `npm run bom:cbom`,
`npm run bom:finalize` and `npm run bom:validate`.

The BOM timestamp is the commit time of the last change to the BOM inputs, not
the current wall clock. Running the command twice on the same commit produces
identical files. That is what makes the CI refresh commit useful instead of
noisy.

## How the CBOM stays accurate

`crypto-inventory.json` is intentionally declarative. Each entry records:

- the CycloneDX crypto asset type and properties (primitive, curve, padding,
  mode, OID, security level, functions);
- the provider that implements it (`OpenBao`, `node:crypto`, `@noble/curves`);
- one or more source patterns and, optionally, files to search.

`scripts/generate-cbom.mjs` fails when:

- an inventory evidence pattern no longer appears in the source;
- a direct dependency looks like a cryptography library but is not mapped in
  `dependencyProviders` (or explicitly ignored);
- a weakly-typed or out-of-scope algorithm (`md5`, `sha1`, `aes-128`,
  `chacha20`, `ml-kem`, `rsa-1024`, ...) appears in a string literal without an
  entry in `ignoredLiterals`;
- an `ignoredLiterals` entry is not explained by a `driftWatch` pattern, or a
  `driftWatch` entry has no reason.

The generated CBOM records the actual file and line for every evidence match
under `evidence.occurrences`. Adding a new algorithm therefore requires a code
change and an inventory change in the same pull request.

### Adding a cryptographic asset

1. Add the algorithm or material to `crypto-inventory.json`.
2. Add a provider if a new library or service implements it.
3. Point `detect` at stable identifiers in the code (`ecdsa-p256`, not a
   comment that may be reworded), or use `evidenceFiles` for non-source
   evidence.
4. Run `npm run bom` and commit `sbom/` with the source change.

If an algorithm is only declared for compatibility and never used (for example
OpenBao's HMAC or AES-GCM key types in the client type union), add a
`driftWatch` entry with a reason and list the exact literal in
`ignoredLiterals` instead of claiming it as an active asset.

## CI/CD

`.github/workflows/bom.yml` runs only when started manually
(`workflow_dispatch`) from the Actions tab. It has no push, pull request,
schedule or release triggers.

On every run it:

1. generates and validates both documents;
2. checks them against the official CycloneDX 1.6 JSON schema;
3. uploads them as the `bom` Actions artifact (90 days);
4. on `main`, commits a refreshed `sbom/` when the generated files differ;
5. attests provenance with GitHub Artifact Attestations;
6. publishes:
   - the rolling `bom-latest` pre-release for the default branch;
   - optionally to GHCR as an OCI artifact;
   - optionally to Dependency-Track.

Stable download URLs for the default branch:

```text
https://github.com/<owner>/<repo>/releases/download/bom-latest/sbom.cdx.json
https://github.com/<owner>/<repo>/releases/download/bom-latest/cbom.cdx.json
```

Verify the provenance of a downloaded file:

```bash
gh attestation verify sbom.cdx.json --repo <owner>/<repo>
```

### Optional publishing configuration

Repository variables:

| Variable | Effect |
| --- | --- |
| `PUBLISH_BOM_OCI` | Set to `true` to push the BOMs to `ghcr.io/<owner>/<repo>/bom` using ORAS. Tags are `sha-<commit>`, `latest` on `main`, and the release tag on releases. |
| `DEPENDENCY_TRACK_URL` | Base URL of a Dependency-Track instance. Setting it enables SBOM upload. |

Repository secret:

| Secret | Effect |
| --- | --- |
| `DEPENDENCY_TRACK_API_KEY` | API key with `BOM_UPLOAD` permission; required when `DEPENDENCY_TRACK_URL` is set. |

Pull the OCI artifact:

```bash
oras pull ghcr.io/<owner>/<repo>/bom:latest
```

### Branch protection

When run on `main`, the refresh commit uses `GITHUB_TOKEN`, so it does not
trigger another workflow run. If `main` is protected against bot pushes, the
step is marked `continue-on-error`; regeneration, validation, artifact upload
and release publication still succeed. In that case, merge the `npm run bom`
output through a normal pull request instead.

## Dependency updates

`.github/dependabot.yml` opens weekly npm and GitHub Actions updates. Because
the BOM workflow no longer runs automatically, regenerate `sbom/` with
`npm run bom` (or dispatch the workflow) after merging a dependency update.

## Scope and caveats

- The SBOM describes the npm dependency graph in `package-lock.json`; it does
  not inventory operating-system packages or the OpenBao server installation.
- The CBOM describes this package's code and its expected OpenBao usage. The
  OpenBao listener's TLS version, cipher suites and key storage backend are
  deployment configuration and are not asserted here.
- Evidence is collected statically. It proves where an algorithm appears in the
  source, not that a particular deployment enables it.
- The CBOM records OpenBao 2.7.2 as the verified server version. Update the
  `openbao` provider in `crypto-inventory.json` when the verified version
  changes.

# Contributing to credo-openbao-kms

Thank you for your interest in improving `credo-openbao-kms`. This is a
community project maintained by AyanWorks Technology Solutions Pvt. Ltd. and
open to outside contributions.

By participating in this project you agree to follow the
[Contributor Covenant Code of Conduct, version 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Report unacceptable behaviour privately to the repository maintainers.

## Ways to contribute

- Report bugs and usability problems with a GitHub issue.
- Propose features or API changes with a GitHub issue before writing code.
- Improve documentation, examples and tests.
- Submit pull requests that fix a bug or implement an agreed feature.

## Reporting bugs and security issues

Use [GitHub Issues](https://github.com/sovio-id/credo-openbao-kms/issues) for
regular bugs and feature requests.

**Do not open a public issue for a security vulnerability.** Follow the
disclosure process in [SECURITY.md](SECURITY.md) instead.

## Development setup

Prerequisites:

- [Bun](https://bun.sh/) 1.4 or newer
- Node.js 22 or newer (Credo 0.7 requires a modern Node.js runtime)

Install dependencies and run the checks:

```bash
bun install
bun run fmt:check
bun run check
bun test
bun run build
```

The most useful scripts:

| Script | Purpose |
| --- | --- |
| `bun run fmt` | Format source, tests, scripts and configuration |
| `bun run fmt:check` | Verify formatting without writing |
| `bun run check` | Type-check the project |
| `bun test` | Run the offline unit tests |
| `bun run build` | Compile to `build/` with type declarations |
| `npm run bom` | Regenerate and validate the SBOM and CBOM in `sbom/` |
| `bun run live-check` | Run the end-to-end check against a live OpenBao |
| `bun run ci` | Format check, type check, tests and build |

## Coding conventions

- TypeScript, ESM, strict mode. Match the style of the surrounding code.
- Keep the package dependency-free where possible. OpenBao access goes through
  the `OpenBaoClient` interface.
- Add or update tests for behaviour changes. Offline tests belong in `test/`.
- Run `bun run fmt` before opening a pull request.
- Do not commit generated output (`build/`), `node_modules/` or secrets.

## Pull requests

1. Fork the repository and create a feature branch from `main`.
2. Make your change in small, focused commits.
3. Sign off every commit using the Developer Certificate of Origin:

   ```bash
   git commit -s
   ```

   The sign-off certifies that you have the right to submit the contribution
   under the project license. See
   <https://developercertificate.org/>.
4. Make sure `bun run ci` passes.
5. Add a changeset (see [Release notes and versioning](#release-notes-and-versioning)).
6. Open a pull request against `main` and link the related issue. Describe the
   problem, the approach and any compatibility or security impact.
7. Address review comments by pushing additional commits or amending your
   branch. Keep the history readable.

## Commit messages

Use a short subject line, then a blank line and a body that explains why the
change is needed and how it was implemented. Reference issues with
`Resolves #<number>` where applicable.

## Release notes and versioning

Release notes are collected with [Changesets](https://github.com/changesets/changesets) while the work is done, instead of being reconstructed at release time. The package is `@sovio-id/credo-openbao-kms`; `package.json` and `jsr.json` always carry the same version.

### When to add a changeset

Add one to every pull request that changes what a consumer of the package gets: features, fixes, API changes, behaviour changes, and dependency updates that matter at runtime. Pull requests that only touch documentation, CI, demos, scripts or tests pass the **Changeset check** without one. A change that is neither and still needs no release note (a pure refactor, for example) takes an empty changeset: `npm run changeset -- --empty`.

### How to add a changeset

```bash
npm run changeset
```

The prompt asks for the bump type and a summary. Write the summary for the people reading the release notes: what changed and what a consumer has to do about it. Commit the generated `.changeset/*.md` file with your pull request.

While the package is below 1.0.0, a `minor` bump is also the right choice for a breaking change, and `major` is kept for the 1.0.0 release.

| Bump | Use it for |
| --- | --- |
| `patch` | Bug fixes, documentation shipped in the package, internal changes with no visible effect |
| `minor` | New features and backwards-compatible API additions; breaking changes while below 1.0.0 |
| `major` | Breaking changes to the public API, the Transit key layout or the stored metadata once the package is 1.0.0 or later |

### How a release is cut

1. Changesets merged into `main` are collected by the **Version Packages** workflow into a pull request named `chore: version packages`. It bumps `package.json`, `package-lock.json` and `jsr.json` together and prepends the entries to `CHANGELOG.md`.
2. A maintainer runs `npm run bom` on that pull request's branch and commits the refreshed `sbom/` files, as in earlier releases, because they record the package version. Then the maintainer reviews and merges the pull request.
3. A maintainer creates a GitHub release with the tag `vX.Y.Z` on the merge commit, using the new `CHANGELOG.md` entry as the release notes. Publishing the release starts the existing **Publish to npm** workflow (with provenance, from the `Production` environment) and the **Publish to JSR** workflow. The Changesets workflows never publish, tag or create releases.

## License

`credo-openbao-kms` is licensed under the
[Apache License, Version 2.0](LICENSE). By submitting a contribution you agree
that it is licensed under the same terms.

For a longer walkthrough of the fork, branch and pull request workflow, see
GitHub's guide to
[contributing to a project](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project).

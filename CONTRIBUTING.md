# Contributing to credo-ts-openbao

Thank you for your interest in improving `credo-ts-openbao`. The project is part
of the LF Decentralized Trust (LFDT) ecosystem and follows the LFDT contribution
practices.

By participating in this project you agree to follow the
[LFDT Code of Conduct](https://lf-decentralized-trust.github.io/governance/governing-documents/code-of-conduct/).

## Ways to contribute

- Report bugs and usability problems with a GitHub issue.
- Propose features or API changes with a GitHub issue before writing code.
- Improve documentation, examples and tests.
- Submit pull requests that fix a bug or implement an agreed feature.

## Reporting bugs and security issues

Use [GitHub Issues](https://github.com/AyanWorks/credo-ts-openbao/issues) for
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
5. Open a pull request against `main` and link the related issue. Describe the
   problem, the approach and any compatibility or security impact.
6. Address review comments by pushing additional commits or amending your
   branch. Keep the history readable.

## Commit messages

Use a short subject line, then a blank line and a body that explains why the
change is needed and how it was implemented. Reference issues with
`Resolves #<number>` where applicable.

## License

`credo-ts-openbao` is licensed under the
[Apache License, Version 2.0](LICENSE). By submitting a contribution you agree
that it is licensed under the same terms.

For a longer walkthrough of the fork, branch and pull request workflow, see the
[LFDT GitHub Contribution Guide](https://lf-decentralized-trust.github.io/governance/guidelines/github-contribution-guide/).

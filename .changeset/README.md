# Changesets

This folder holds pending release notes. Each pull request that changes the
package adds a small markdown file here; when a release is prepared, the files
are turned into the version bump and the `CHANGELOG.md` entry.

Add a changeset with:

```bash
npm run changeset
```

Use `npm run changeset -- --empty` when a change needs no release note. See the
"Release notes and versioning" section of [CONTRIBUTING.md](../CONTRIBUTING.md)
for what patch, minor and major mean here and how a release is cut and
published.

More about Changesets: <https://github.com/changesets/changesets>

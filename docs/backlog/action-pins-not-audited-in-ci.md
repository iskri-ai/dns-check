---
worth: later
added: 2026-11-14
---
# action pins are not audited in CI

Only the manual check in the README "Action pins" bullet confirms that a pinned SHA is the commit of the official tag in its version comment. Dependabot raises no alerts for actions pinned by SHA. zizmor could run three online audits on every PR with the read-only `GITHUB_TOKEN`:

- `impostor-commit`: the commit exists in the official repo, not only in a fork.
- `ref-version-mismatch`: the version comment matches the tag of the SHA.
- `known-vulnerable-actions`: each pin is mapped to its tag and checked against GitHub advisories.

The costs: zizmor becomes a dev dependency that runs with a token in CI, and CI starts calling the GitHub API. Deliberate findings, such as `persist-credentials` on the `.state` checkout, need inline ignore comments. The audits run only when a PR runs, so they are not ongoing monitoring, and they can't show that upstream code is safe. Check the audit names against the current zizmor release before use.

Deferred when Dependabot was added, which kept the checks manual. It becomes worth doing if pins start changing by hand often, or if an advisory for a pinned action goes unnoticed.

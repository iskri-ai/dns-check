---
worth: yes
where: .github/workflows/ci.yml:20
added: 2026-11-14
---
# the uv binary version is not updated by Dependabot

Both workflows pin uv with `version: "0.13.5"` in the `astral-sh/setup-uv` step, also at `.github/workflows/dns-check.yml:31`. No Dependabot ecosystem updates that input, so it moves only when someone bumps it by hand. The Dependabot updater runs its own uv (dependabot-core main uses 0.13.7), so a uv PR can write `uv.lock` with a newer uv than CI and the monitor install. If uv 0.13.5 can't read that lock, `uv sync --locked` fails loudly, so the gap doesn't fail silently. `.python-version` has the same gap.

Deferred when Dependabot was added, as out of its scope.

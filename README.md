# dns-check

A scheduled GitHub Actions job that checks the DNS setup of iskri.io against [expected.yaml](expected.yaml) and reports to Telegram.

Every 30 minutes the job queries the .io TLD servers, the Selectel nameservers and RDAP directly. It sends a Telegram message when a check changes its status, and a daily summary.

## Checks

- **delegation**: the .io servers delegate the domain to exactly the nameservers in `expected.yaml`.
- **soa**: every Selectel address returns the same SOA serial. Each address gets 8 queries in each pass, the check and its re-check, so one lagging backend instance is unlikely to hide.
- **expiry**: according to RDAP, the registration does not expire within `min_days_left` days.
- **records**: each listed record set matches exactly on every Selectel address.

Each check ends as `ok`, `fail` (the domain is wrong) or `unknown` (an outside source, the .io servers or RDAP, could not be checked). Anything uncertain never ends as `ok`. A failing check is re-checked once after 2 minutes, and the second result counts.

## Messages

- **Status changes**: one message per run, only when a status changed. A recovery shows how long the problem lasted.
- **Daily summary** at about 09:17 Asia/Almaty (04:17 UTC): every check with its key facts, current problems, and a warning when `master` has had no commit for 50 days.
- **Run aborted**: the job could not finish its work, for example because `expected.yaml` is invalid or Telegram is unreachable. This message repeats on every run until the cause is fixed. The job then also fails, and GitHub emails whoever committed the workflow.

## Changing expected.yaml

The comments at the top of `expected.yaml` describe the format. The loader rejects a file with any mistake that could let a check pass silently, and CI loads the real file on every pull request.

A mismatch is reported while either change is pending. To avoid a `fail` message and the recovery message after it, land both changes between two scheduled checks, which start at :07 and :37 past each hour.

## Setup

Do these steps once, in this order.

1. **Telegram.** The org secret `TELEGRAM_BOT_TOKEN`, the org variable `TELEGRAM_CHAT_ID` and the repo variable `TELEGRAM_THREAD_ID`. On GitHub Free, private repos can't use org secrets and variables, so this repo must stay public.
2. **Actions policy** (repo settings, Actions, General): allow only actions by GitHub and `astral-sh/setup-uv`, and require actions to be pinned to a full commit SHA.
3. **`master` ruleset**: require a pull request and the `ci` status check, block force pushes and deletion, with an empty bypass list. The scheduled job can push, so without this ruleset any step could change the monitor itself.
4. **`state` branch**, created by hand:

   ```sh
   git switch --orphan state
   echo '{}' > state.json
   git add state.json
   git commit -m 'chore(state): add empty state'
   git push origin state
   git switch master
   ```

   Then a **`state` ruleset** that blocks deletion and force pushes but allows normal pushes.

## Operations

- **Manual run**, from `master` only:

  ```sh
  gh workflow run dns-check.yml --ref master
  gh workflow run dns-check.yml --ref master -f heartbeat=true
  ```

  A manual run on another branch uses that branch's workflow file with the repo secrets.
- **Schedule disabled.** GitHub disables scheduled workflows in a public repo after 60 days without activity. The daily summary warns from day 50, and a missing summary is the last signal. To restore the schedule:

  ```sh
  gh workflow enable dns-check.yml
  ```

## Development

```sh
uv sync
uv run pytest
uv run mypy
```

Tests make no network calls. pytest-socket blocks them.

## Known limits

- Unlisted names and record types are not checked. TTLs are not compared.
- The Selectel addresses are anycast. The job sees only the Selectel site nearest the GitHub runner.
- A Selectel instance with a current serial and wrong records is caught only in runs where a record query reaches it.
- Unreachable .io servers don't change the delegation status, because all .io servers serve the same registry data. The daily summary shows how many answered.
- The Telegram chat and thread IDs are variables, so GitHub shows them in the public run logs. They're useless without the bot token, which is a masked secret.

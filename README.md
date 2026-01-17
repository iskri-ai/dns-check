# dns-check

A scheduled GitHub Actions job that checks the DNS setup of iskri.io against [expected.yaml](expected.yaml) and reports to Telegram.

Every 30 minutes the job queries the .io TLD servers, the Selectel nameservers and RDAP directly. It sends a Telegram message when a check changes its status, and a daily summary.

## Checks

- **delegation**: the .io servers delegate the domain to exactly the nameservers in `expected.yaml`.
- **soa**: every Selectel address returns the same SOA serial. Each address gets 8 queries per pass, so one lagging backend instance is unlikely to hide.
- **expiry**: RDAP shows at least `min_days_left` days until the registration expires, and no active auto-renew period. During that period the check fails even when the renewal is paid.
- **records**: each listed record set matches exactly on every Selectel address.

Each check ends as `ok`, `fail` (a problem was found, such as a wrong record, an unusable answer from a Selectel server or a registration about to expire) or `unknown` (too little could be read to decide, for example because no response arrived). A confirmed problem outranks anything unreadable, and nothing uncertain ends as `ok`, apart from the delegation exception under Known limits. An `unknown` check runs once more after 2 minutes, and the second result counts. A `fail` is reported in the run that found it.

A run that completes ends green on GitHub even when checks fail or are unknown, so a green job doesn't mean healthy DNS. Only an aborted run fails the job.

## Messages

- **Status changes**: one message per run, only when a status changed. A recovery shows how long the problem lasted.
- **Daily summary** at about 09:17 Asia/Almaty (04:17 UTC): every check with its key facts, current problems, and a warning when `master` has had no commit for 50 days.
- **Run aborted**: the job could not finish its work, for example because `expected.yaml` is invalid or Telegram is unreachable. Each aborted run attempts this message and fails the job, until the cause is fixed. Whether GitHub also emails someone depends on its [rules for scheduled workflows](https://docs.github.com/en/actions/concepts/workflows-and-actions/notifications-for-workflow-runs) and that user's [notification settings](https://docs.github.com/en/subscriptions-and-notifications/how-tos/managing-github-actions-notifications).

## Changing expected.yaml

The comments at the top of `expected.yaml` describe the format. The loader checks the structure, the record names and the values before the first query, and CI loads the real file on every pull request to `master`. A valid file can still be wrong. Removing a record from the file stops checking it, without a message.

A mismatch is reported while either change is pending. To avoid a `fail` message and the recovery message after it, land both changes while no check is running. Checks are scheduled at :07 and :37 past each hour, GitHub can start them late, and a run takes a few minutes.

Any zone edit, even to an unlisted record, changes the SOA serial. A run that queries the nameservers while they update can report a `soa` fail, followed by a recovery.

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
- A second, different problem on a check that is already failing sends no message, because messages report status changes. It shows in the daily summary only if it is still present then.
- The Selectel addresses are anycast. The job sees only the Selectel site nearest the GitHub runner.
- A Selectel instance with a current serial and wrong records is caught only in runs where a record query reaches it.
- Delegation ignores .io servers that give no usable answer, because all .io servers serve the same registry data. It is `ok` when at least one server gives a usable referral and every referral matches, `fail` on any wrong or missing delegation, and `unknown` when no server gives a usable answer. The daily summary shows how many answered.
- The Telegram chat and thread IDs are variables, so GitHub shows them in the public run logs. They're useless without the bot token, which is a masked secret.

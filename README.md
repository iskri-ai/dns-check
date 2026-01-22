# dns-check

A GitHub Actions job, started by cron-job.org, that checks the DNS setup of iskri.io against [expected.yaml](expected.yaml) and reports to Telegram.

Every 30 minutes the job queries the .io TLD servers, the Selectel nameservers and RDAP directly. It sends a Telegram message when a check changes its status, and a daily summary.

## Checks

- **delegation**: the .io servers delegate the domain to exactly the nameservers in `expected.yaml`.
- **soa**: every Selectel address returns the same SOA serial. Each address gets 8 queries per pass, so one lagging backend instance is unlikely to hide.
- **expiry**: RDAP shows at least `min_days_left` days until the registration expires, and no active auto-renew period. During that period the check fails even when the renewal is paid.
- **records**: each listed record set matches exactly on every Selectel address.

Each check ends as `ok`, `fail` (a problem was found, such as a wrong record, an unusable answer from a Selectel server or a registration about to expire) or `unknown` (too little could be read to decide, for example because no response arrived). A confirmed problem outranks anything unreadable, and nothing uncertain ends as `ok`, apart from the delegation exception under Known limits. An `unknown` check runs once more after 2 minutes, and the second result counts. A `fail` is reported in the run that found it.

A run that completes ends green on GitHub even when checks fail or are unknown, so a green job doesn't mean healthy DNS. Only an aborted run fails the job.

## Messages

- **Status changes**: one message per run, only when a status changed. A recovery shows how long the check spent in its previous status. After `fail`, then `unknown`, then `ok`, that covers only the `unknown` part.
- **Daily summary** at about 09:23 Asia/Almaty (04:23 UTC): every check with its key facts and current problems.
- **Run aborted**: the job could not finish its work, for example because `expected.yaml` is invalid or Telegram is unreachable. Each aborted run attempts this message and fails the job, until the cause is fixed. If a run aborts before saving the state, the next run may report the same changes again. For runs started by cron-job.org, GitHub may also [email the token owner](https://docs.github.com/en/actions/concepts/workflows-and-actions/notifications-for-workflow-runs), depending on their [notification settings](https://docs.github.com/en/subscriptions-and-notifications/how-tos/managing-github-actions-notifications).

## Changing expected.yaml

The comments at the top of `expected.yaml` describe the format. The loader checks the structure, the record names and the values before the first query, and CI loads the real file on every pull request to `master`. A valid file can still be wrong. Removing a record from the file stops checking it, without a message.

A mismatch is reported while either change is pending. To avoid a `fail` message and the recovery message after it, land both changes while no check is running. cron-job.org calls at about :08 and :38 past each hour and at 04:23 UTC for the summary. A run can start later than its call, and it takes a few minutes.

Any zone edit, even to an unlisted record, changes the SOA serial. A run that queries the nameservers while they update can report a `soa` fail, followed by a recovery.

## Setup

Do these steps once, in this order.

1. **Telegram.** The org secret `TELEGRAM_BOT_TOKEN`, the org variable `TELEGRAM_CHAT_ID` and the repo variable `TELEGRAM_THREAD_ID`. On GitHub Free, private repos can't use org secrets and variables, so this repo must stay public.
2. **Actions policy** (repo settings, Actions, General): allow only actions by GitHub and `astral-sh/setup-uv`, and require actions to be pinned to a full commit SHA.
3. **`master` ruleset**: require a pull request and the `ci` status check, block force pushes and deletion, with an empty bypass list. The scheduled job can push, so without this ruleset any step could change the monitor itself.
4. **Dependabot** (repo settings, Advanced Security): turn on the dependency graph, Dependabot alerts and Dependabot security updates. Alerts read the graph, so without it the alert list stays empty, as if nothing were vulnerable.
5. **`state` branch**, created by hand:

   ```sh
   git switch --orphan state
   echo '{}' > state.json
   git add state.json
   git commit -m 'chore(state): add empty state'
   git push origin state
   git switch master
   ```

   Then a **`state` ruleset** that blocks deletion and force pushes but allows normal pushes.
6. **External scheduler**: the token and the two cron-job.org jobs described under [External scheduler](#external-scheduler).

## External scheduler

The GitHub schedule trigger started few of the runs in this repo, so the workflow has none. [cron-job.org](https://cron-job.org) starts the scheduled runs through the GitHub API instead, with two jobs:

- **dns-check checks**: every hour at :08 and :38, body `{"ref":"master","inputs":{"heartbeat":"false"}}`.
- **dns-check daily summary**: daily at 04:23 UTC, body `{"ref":"master","inputs":{"heartbeat":"true"}}`.

Both send `POST https://api.github.com/repos/iskri-ai/dns-check/actions/workflows/dns-check.yml/dispatches` with the headers `Accept: application/vnd.github+json`, `Authorization: Bearer <token>`, `X-GitHub-Api-Version: 2026-03-10` and `Content-Type: application/json`. With this version, a successful call returns 200 with the ID and URLs of the new run. Each job has cron-job.org notifications on for a failed call, a success after a failure and a disabled job. The minutes avoid the top of the hour, when cron-job.org and the GitHub API are busiest. The cron-job.org account uses 2FA and an email address outside iskri.io.

The token is a fine-grained personal access token of `gurza`, with `iskri-ai` as the resource owner, access to `dns-check` only, and the Actions read and write permission plus the Metadata read that GitHub adds to every token. It is valid for one year, and GitHub emails the owner before it expires.

A disabled workflow, an expired token or a file GitHub can't parse makes the dispatch call fail, and cron-job.org emails about it. A missing daily summary with no red run can mean the summary job isn't calling, or its body doesn't send `heartbeat=true`.

To rotate the token:

1. Create a new token with the same settings.
2. Replace the `Authorization` header in both jobs.
3. Start one job by hand in cron-job.org and check that its run passes.
4. Revoke the old token.

To hand over the scheduler, the new maintainer issues their own token, takes over the jobs in their own cron-job.org account or the existing one, revokes the old token and updates the owner in this section.

## Operations

- **Manual run**, from `master` only:

  ```sh
  gh workflow run dns-check.yml --ref master
  gh workflow run dns-check.yml --ref master -f heartbeat=true
  ```

  A manual run on another branch uses that branch's workflow file with the repo secrets.
- **Workflow changes.** After a change to `dns-check.yml` merges, start a manual run from `master` and check that it passes. CI doesn't check this file. A file GitHub can't parse makes the dispatch call fail, and cron-job.org emails about it.
- **Action pins.** Before merging any PR that changes an action pin, from Dependabot or by hand, read the release notes and check that each new SHA is the commit of the tag in its version comment, in the official repo. Use the action's own repo and tag:

  ```sh
  git ls-remote --exit-code --tags https://github.com/actions/checkout v7.0.1 'v7.0.1^{}'
  ```

  The command fails if the tag doesn't exist. If a line ending in `^{}` appears, the tag is annotated and that line holds the commit SHA.
- **Dependency updates.** Dependabot checks monthly and groups eligible version updates into one PR per ecosystem, for releases at least 7 days old. Security updates for Python packages open without waiting for the schedule or the cooldown, when Dependabot can resolve a fixed version. Merge each PR by hand, after CI passes and you read the release notes. For an actions PR, also do the pin check above. After merging a PR that changes `dns-check.yml` or a runtime package (one that `uv sync --no-dev` installs), start a manual run from `master` and check that it passes. An actions PR almost always changes `dns-check.yml`.

## Development

```sh
uv sync
uv run pytest
uv run mypy
uv run ruff check
uv run ruff format
```

Tests make no network calls. pytest-socket blocks them.

## Known limits

- Unlisted names and record types are not checked. TTLs are not compared.
- A second, different problem on a check that is already failing sends no message, because messages report status changes. It shows in the daily summary only if it is still present then.
- The Selectel addresses are anycast. The job sees only the Selectel site nearest the GitHub runner.
- The job queries the .io servers and the Selectel nameservers over IPv4 only. A problem on their IPv6 addresses alone goes unnoticed.
- A Selectel instance with a current serial and wrong records is caught only in runs where a record query reaches it.
- Delegation ignores .io servers that give no usable answer, because all .io servers serve the same registry data. It is `ok` when at least one server gives a usable referral and every referral matches, `fail` on any wrong or missing delegation, and `unknown` when no server gives a usable answer. The daily summary shows how many answered.
- The Telegram chat and thread IDs are variables, so GitHub shows them in the public run logs. They're useless without the bot token, which is a masked secret.
- Dependabot raises no alerts for actions pinned by SHA. A fixed action arrives with the monthly update after its 7-day cooldown, so bump it by hand when an advisory comes out.

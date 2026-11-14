---
worth: yes
where: README.md:67
added: 2026-11-14
---
# the scheduler token expires on 2027-11-14

The fine-grained token in both cron-job.org jobs expires on 2027-11-14. GitHub emails the owner beforehand. If it lapses, every dispatch fails, so scheduled checks and the daily summary stop.

Rotate it around 2027-11-07, and use the rotation to test the cron-job.org failure email, which has never been tested. This changes the order of the README rotation steps. Create the new token, check that both jobs notify by email after one failure, and revoke the old token. Once the next call shows as failed in the job history, put the new token into both jobs, whether or not the email arrived. Start one job by hand in cron-job.org and check that its GitHub run passes. Then check that the failure email arrived. Also check that the API version in both jobs is still supported.

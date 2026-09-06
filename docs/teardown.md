# Teardown Checklist

Run this **after** the repository is published and all evidence has been captured. Nothing below is recoverable once done.

Everything in this lab is either free-tier or costs cents, with two exceptions: the second trail's duplicate management events, and anything left enabled long-term. This checklist stops all of it.

---

## Before you tear down — confirm you have what you need

Do not delete anything until these are true:

- [ ] Repository is pushed and renders correctly on GitHub
- [ ] All 24 screenshots are committed and open correctly in the browser
- [ ] All three evidence JSON exports are committed
- [ ] Redaction verified — no account ID, source IP, access key ID, or email in any committed file or image
- [ ] You can answer the five project questions without opening the console

Once the account is torn down you cannot go back and take a screenshot you forgot.

---

## 1. IAM — remove the test identity

The escalation target from Session 4. This is also the containment exercise, so **do it in this order** and let CloudTrail record each step.

```bash
# Containment first — deactivate the credential
aws iam list-access-keys --user-name test-analyst-user
aws iam update-access-key \
  --user-name test-analyst-user \
  --access-key-id <AKIA...> \
  --status Inactive

# Eradication — strip permissions
aws iam detach-user-policy --user-name test-analyst-user \
  --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
aws iam detach-user-policy --user-name test-analyst-user \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Delete the key, then the user
aws iam delete-access-key --user-name test-analyst-user --access-key-id <AKIA...>
aws iam delete-user --user-name test-analyst-user
```

- [ ] Access key deactivated
- [ ] Both policies detached
- [ ] Access key deleted
- [ ] User deleted

**Capture this before deleting anything else.** Your own response actions generate `UpdateAccessKey`, `DetachUserPolicy`, `DeleteAccessKey`, and `DeleteUser` events. Screenshot Event history filtered to `Read-only = false` afterward — that is a logged, timestamped response timeline, and it is stronger evidence than a bulleted list of intentions.

Save as: `screenshots/25-containment-actions.png`

---

## 2. CloudWatch — alarms and metric filters

```bash
aws cloudwatch delete-alarms --alarm-names \
  ALARM-RootAccountUsage \
  ALARM-IAMPrivilegeEscalation \
  ALARM-CloudTrailTampering
```

- [ ] Three alarms deleted

Metric filters, via console: CloudWatch → Log Management → `aws-cloudtrail-logs-<account>-<suffix>` → Metric filters → select all three → Delete.

- [ ] `RootAccountUsage` filter deleted
- [ ] `IAMPrivilegeEscalation` filter deleted
- [ ] `CloudTrailTampering` filter deleted

---

## 3. CloudWatch Logs — the log group

This is the one that quietly accrues storage cost if left.

```bash
aws logs delete-log-group --log-group-name aws-cloudtrail-logs-<account>-<suffix>
```

- [ ] Log group deleted

---

## 4. SNS — topic and subscription

Deleting the topic removes the subscription with it.

```bash
aws sns delete-topic \
  --topic-arn arn:aws:sns:us-east-1:<account>:cloudtrail-security-alerts
```

- [ ] Topic deleted
- [ ] Confirm no further alert emails arrive

---

## 5. CloudTrail — the trail

`secondary-trail` was already deleted during Session 4 testing. Only `primary-trail` remains.

```bash
aws cloudtrail stop-logging --name primary-trail
aws cloudtrail delete-trail --name primary-trail
```

- [ ] `primary-trail` stopped
- [ ] `primary-trail` deleted
- [ ] Confirm `aws cloudtrail describe-trails` returns nothing for this account

Note: deleting a trail does **not** delete the logs already in S3. That is the next step.

---

## 6. S3 — the log bucket

CloudTrail will have written a few thousand objects. The bucket must be emptied before it can be deleted.

```bash
# Check what you are about to delete
aws s3 ls s3://cloudtrail-logs-example --recursive --summarize | tail -3

# Empty it
aws s3 rm s3://cloudtrail-logs-example --recursive

# Delete the bucket itself
aws s3api delete-bucket --bucket cloudtrail-logs-example
```

- [ ] Object count checked before deletion
- [ ] Bucket emptied
- [ ] Bucket deleted

If versioning was ever enabled, `s3 rm --recursive` leaves delete markers and the bucket will refuse to delete. In that case remove versions via the console: S3 → bucket → Empty, then Delete.

---

## 7. Anything else that was enabled

- [ ] **GuardDuty** — was never enabled in this build. If you turned it on to experiment, disable it. It bills after the trial period.
- [ ] **AWS Config** — not enabled. Verify it is still off; it bills per configuration item recorded.
- [ ] **S3 data events** — not enabled in this build. If you enabled them on a test bucket, confirm the event selector is removed.
- [ ] **CloudWatch Insights / Contributor Insights** — not enabled. Verify.

---

## 8. Keep these

Do **not** remove:

- [ ] **Root MFA** — leave enabled. There is no reason to remove it.
- [ ] **The $5 budget** — leave it. It costs nothing and it is the safety net for whatever you build next.
- [ ] **`ak-admin`** — you will want an admin IAM user for the next project. But **rotate its access key** if it was used for anything you screenshotted:

```bash
aws iam list-access-keys --user-name ak-admin
aws iam delete-access-key --user-name ak-admin --access-key-id <old-AKIA...>
aws iam create-access-key --user-name ak-admin
aws configure   # enter the new credentials
```

- [ ] `ak-admin` access key rotated

The key ID `AKIAEXAMPLEKEYID0001` appears in log exports and possibly in screenshots. A key ID alone is not a secret — the secret access key is what matters, and that was never captured — but rotating costs two minutes and removes any ambiguity.

**Also consider:** `ak-admin` holds `AdministratorAccess` and did not have MFA during this project. That was identified as a genuine finding. Fix it before the next project rather than repeating it.

- [ ] MFA enabled on `ak-admin`

---

## 9. Verify the account is quiet

Wait 48 hours after teardown, then:

```bash
# Should return nothing
aws cloudtrail describe-trails --query 'trailList[*].Name'
aws cloudwatch describe-alarms --query 'MetricAlarms[*].AlarmName'
aws sns list-topics
aws s3 ls
aws iam list-users --query 'Users[*].UserName'
```

- [ ] No trails
- [ ] No alarms
- [ ] No SNS topics
- [ ] No lab buckets
- [ ] Only `ak-admin` remains as an IAM user

Then check Billing → Cost Explorer for the following month and confirm the account has returned to zero or near-zero.

- [ ] Next month's bill confirmed at expected level

---

## Cost summary for the writeup

Worth recording in the README — it is a fair question and most portfolio projects cannot answer it.

| Item | Cost |
|---|---|
| CloudTrail management events, first copy | Free |
| CloudTrail management events, second copy (`secondary-trail`) | ~$2 per 100,000 events; a few hundred events generated |
| S3 storage for logs | Free tier |
| CloudWatch Logs ingestion and storage | Free tier at this volume |
| CloudWatch alarms (3) | Free tier covers 10 |
| SNS email notifications | Free tier covers 1,000 |
| SSE-KMS | **Avoided** — deliberately disabled; would have cost ~$1/month for the key |
| GuardDuty | **Not enabled** |
| S3 data events | **Not enabled** |

Total: under $1 for the entire project.

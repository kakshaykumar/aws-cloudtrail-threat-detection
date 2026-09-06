# Ground Truth Log — Session 4

**Purpose:** Record exactly what was done, when, so the reconstructed timeline in Session 5 can be checked against known activity.

**Timezone:** Local = EST (UTC−4). All CloudTrail timestamps are UTC.
**Account:** 111122223333
**Region:** us-east-1
**Operator:** Self (single-analyst lab). All activity below is simulated adversary emulation performed by the account owner.

---

## Attack 1 — Root account usage

**Scenario:** Unexpected use of the AWS root account
**MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts
**Detection:** `ALARM-RootAccountUsage`

### Actions performed

| # | Action | Local time | UTC |
|---|---|---|---|
| 1 | Root console login (MFA completed) | 01:15:30 | 05:15:30 |
| 2 | Viewed Billing and Cost Management | ~01:15:40 | ~05:15:40 |
| 3 | Viewed IAM | ~01:15:50 | ~05:15:50 |
| 4 | Signed out of root | ~01:16 | ~05:16 |

### Detection result

| Measure | Value |
|---|---|
| Metric datapoint | 3.0 at 05:15:00 UTC |
| Alarm state change | 05:16:54 UTC (OK → ALARM) |
| Email received | 01:16 local / 05:16:54 UTC |
| **Time to alert** | **~1 min 24 sec** (from first action to alarm) |
| Outcome | **TRUE POSITIVE** — detection fired as designed |

### Notes

- Metric counted 3 events from what felt like a single short session — consistent with the console-noise finding from Session 2.
- Viewing IAM while in root mirrors the reconnaissance stage of a real root-compromise pattern, even though this instance was benign.
- Evidence: `12-alarm-triggered-root.png`, `13-alert-email-root.png`

---

## Attack 2 — IAM privilege escalation

**Scenario:** IAM identity granted elevated permissions, then given persistent credentials
**MITRE ATT&CK:** T1136.003 (Create Account: Cloud Account), T1098.003 (Additional Cloud Roles), T1098.001 (Additional Cloud Credentials)
**Detection:** `ALARM-IAMPrivilegeEscalation`

**Safety justification:** `test-analyst-user` was created with no console password and no pre-existing access key, so the granted permissions were not usable by any party during the test window.

### Actions performed

| # | Action | Local time | UTC | Intent |
|---|---|---|---|---|
| 1 | `CreateUser` — test-analyst-user | 01:35:33 | 05:35:33 | Create target |
| 2 | `AttachUserPolicy` — ReadOnlyAccess | 01:37:01 | 05:37:01 | Benign control case |
| 3 | `AttachUserPolicy` — IAMFullAccess | 01:38:17 | 05:38:17 | **Privilege escalation** |
| 4 | `CreateAccessKey` | 01:40:05 | 05:40:05 | **Persistence** |

### Detection result

| Measure | Value |
|---|---|
| Matching events generated | 3 (`AttachUserPolicy` ×2, `CreateAccessKey`) |
| Alarm notifications received | **2** |
| Alarm #1 | datapoint 05:37:00 → ALARM 05:38:06 (≈1 min 5 sec) |
| Alarm #2 | datapoint 05:39:00 → ALARM 05:40:06 (≈1 min 49 sec) |
| Outcome | **TRUE POSITIVE** — but fewer notifications than matching events |

### Key finding — severity lives in `requestParameters`

Steps 2 and 3 produced the **same `eventName`**, from the same identity, same source IP, same session, 76 seconds apart. The only differentiating field:

```
Step 2: "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"    → informational
Step 3: "policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"     → critical
```

An alarm keyed on `eventName` alone cannot separate routine administration from privilege escalation. Severity must be conditional on `requestParameters.policyArn`.

### Notes

- Three events matched the filter but only two notifications arrived. CloudWatch alarms notify on **state transition**, not per event — see the cross-cutting finding at the end of this document.
- `CreateUser` (step 1) was **not detected**. It is absent from the metric filter's event list, so creation of the target identity generated no alert. Coverage gap.
- Step 2 was legitimate administrative work and still triggered the alarm — a **deliberately generated false positive**, documented rather than tuned away.
- The access key created in step 4 has an `AKIA` prefix: long-term, non-expiring, and not subject to MFA. This is the persistence artifact an attacker would want.
- Filtering Event history on `Read-only = false` reduced the entire attack to four lines.
- Evidence: `14-alarm-triggered-iam.png`, `15-alert-email-iam.png`, `16-attach-policy-event.png`, `17-attach-policy-benign.png`

---

## Attack 3 — CloudTrail tampering

**Scenario:** Logging disabled, restored, modified, and destroyed to evade detection
**MITRE ATT&CK:** T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log *(verified against attack.mitre.org 2026-09-03; formerly T1685.002)*
**Detection:** `ALARM-CloudTrailTampering`
**Target:** `secondary-trail` (disposable). `primary-trail` untouched and logging throughout.

### Actions performed

| # | Action | Local time | UTC | Intent |
|---|---|---|---|---|
| 1 | `StopLogging` — secondary-trail | 02:06:01 | 06:06:01 | Go dark |
| 2 | `StartLogging` — secondary-trail | 02:09:20 | 06:09:20 | Restore to look normal |
| 3 | `UpdateTrail` — changed log prefix | 02:10:21 | 06:10:21 | Redirect logging |
| 4 | `UpdateTrail` — second write | 02:10:29 | 06:10:29 | (console follow-up) |
| 5 | `DeleteTrail` — secondary-trail | 02:12:03 | 06:12:03 | Destroy the record |

Collateral events observed but **not** matched by the filter:

| `PutBucketPolicy` on `cloudtrail-logs-example` | 02:10:21 | 06:10:21 |
| `PutBucketPolicy` on `cloudtrail-logs-example` | 02:10:28 | 06:10:28 |

### Detection result

| Measure | Value |
|---|---|
| Matching events generated | **5** |
| Alarm notifications received | **1** |
| Metric datapoint | 1.0 at 06:08:00 (later peaked at 2.0 ≈06:10) |
| Alarm state change | 06:09:29 UTC (OK → ALARM) |
| Returned to OK | 06:14:29 UTC — *after* the trail was already deleted |
| **Time to alert (StopLogging)** | **3 min 28 sec** |
| Outcome | **TRUE POSITIVE — with a significant notification gap** |

### Key finding — alarms notify on state change, not per event

Five matching events produced one email. Once the alarm entered ALARM at 06:09:29, every subsequent action (`StartLogging`, both `UpdateTrail` calls, and `DeleteTrail`) occurred while the alarm was already breaching. No state transition means no notification.

The alarm did not return to OK until 06:14:29 — two and a half minutes after the trail had been deleted.

**Operational impact:** a real attacker executing stop → act → delete inside two minutes would generate a single alert. By the time a responder opened it, the trail would be gone. The detection logic is sound; the notification model is the weak link. Remediating this requires per-event delivery (EventBridge rule → SNS) or SIEM ingestion rather than CloudWatch metric alarms.

### Key finding — ingestion lag can mislead a timeline

`StopLogging` occurred at 06:06:01, but the metric datapoint landed at 06:08:00 and the alarm fired at 06:09:29. The alert arrived seconds after `StartLogging` was clicked, creating the false impression that the alert corresponded to the restart rather than the stop.

Alert arrival time is **not** event time. Timelines must be built from `eventTime` in CloudTrail, not from when the notification appeared.

### Key finding — log storage tampering is out of scope

Modifying the trail prefix generated two `PutBucketPolicy` events against the S3 log bucket. Neither matched the filter. A ruleset scoped to `cloudtrail.amazonaws.com` does not cover attacks on the storage layer — bucket policy changes, lifecycle expiry rules, or object deletion.

### Verification — primary trail survived

```
aws cloudtrail get-trail-status --name primary-trail
{
    "IsLogging": true,
    "LatestCloudWatchLogsDeliveryTime": "2026-09-03T02:14:21-04:00",
    "TimeLoggingStopped": ""
}
```

The two-trail design worked as intended: `secondary-trail` was destroyed while `primary-trail` recorded every step of its destruction, including the `DeleteTrail` call itself.

### Notes

- `DeleteTrail` executed with **no confirmation prompt**. Destroying an audit trail was a single click.
- Evidence: `18-alarm-triggered-tampering.png`, `19-alert-email-tampering.png`, `20-stoplogging-event.png`, `21-primary-trail-survived.png`

---

## Containment and eradication — performed 2026-09-06

Response executed against the identity created during Attack 2. Performed deliberately so that the response itself would be recorded, producing a logged and timestamped response timeline rather than a written description of intended actions.

### Actions performed

| # | Time (UTC) | Local | Action | Target | NIST phase |
|---|---|---|---|---|---|
| 1 | 06:33:44 | 02:33:44 | `UpdateAccessKey` → Inactive | `AKIAEXAMPLEKEYID0001` | **Containment** |
| 2 | 06:34:13 | 02:34:13 | `DetachUserPolicy` | `IAMFullAccess` | Eradication |
| 3 | 06:34:20 | 02:34:20 | `DetachUserPolicy` | `ReadOnlyAccess` | Eradication |
| 4 | 06:34:58 | 02:34:58 | `DeleteAccessKey` | `AKIAEXAMPLEKEYID0001` | Eradication |
| 5 | 06:35:18 | 02:35:18 | `DeleteUser` | `test-analyst-user` | Eradication |

### Measured result

| Measure | Value |
|---|---|
| Time to contain (first action → credential deactivated) | **0 sec** — containment was the first action |
| Time to full eradication (first action → user deleted) | **94 seconds** |
| Response actions logged by CloudTrail | 5 of 5 |

### Ordering rationale

The access key was deactivated **before** permissions were detached. Reversing this order leaves a window in which the credential is still usable with the elevated permissions attached. Containment precedes eradication for that reason.

Note that for a role rather than an IAM user, deactivating a key would not be sufficient — `ASIA` session credentials already issued remain valid until expiry. Role compromise requires session revocation via an `AWSRevokeOlderSessions` policy, not key deactivation alone.

### Verification

**Log integrity confirmed post-incident.** `aws cloudtrail validate-logs` was run against `primary-trail` for the full incident date:

```
Results found for 2026-09-03T00:00:00Z to 2026-09-03T23:59:59Z:

25/25 digest files valid
156/156 log files valid
```

No log file was altered or removed during or after the simulated attack. This is the recovery step that the log file validation setting — enabled at trail creation and not applicable retroactively — exists to support.

Evidence: `25-containment-actions.png`, `26-log-validation.png`, `evidence/log-validation-output.txt`

---

## Summary

| Attack | Detection | Matching events | Notifications | Time to alert | Result |
|---|---|---|---|---|---|
| Root account usage | ALARM-RootAccountUsage | 3 | 1 | ~1 min 24 sec | True positive |
| IAM privilege escalation | ALARM-IAMPrivilegeEscalation | 3 | 2 | ~1–2 min | True positive |
| CloudTrail tampering | ALARM-CloudTrailTampering | 5 | 1 | ~3 min 28 sec | True positive |

**Detection coverage:** 3 of 3 scenarios detected by an automated alarm.

**Response:** containment and eradication performed and logged. 5 of 5 response actions recorded. Full eradication in 94 seconds.

**Log integrity:** verified post-incident — 25/25 digest files and 156/156 log files valid.

**False positives observed:** 1 — `AttachUserPolicy` with `ReadOnlyAccess` (legitimate administrative work) triggered the IAM alarm. Deliberately generated as a control case, documented rather than tuned away.

---

## Cross-cutting findings

### 1. Notification model, not detection logic, is the limiting factor

Across all three attacks, **11 matching events produced 4 notifications**. CloudWatch metric alarms fire on state transition. Any burst of related activity collapses into a single alert, and the alarm stays red — and silent — for the remainder of the burst.

This is the single most important architectural limitation of the build. Per-event notification requires EventBridge rules or SIEM ingestion.

### 2. Alert time ≠ event time

Time to alert ranged from ~1 min to ~3.5 min, driven mainly by CloudWatch Logs ingestion lag. In the tampering test this produced a misleading correlation between an alert and the wrong user action. All timeline reconstruction must use `eventTime`, not notification time.

### 3. Severity is conditional on `requestParameters`, not `eventName`

The same `AttachUserPolicy` event was informational with `ReadOnlyAccess` and critical with `IAMFullAccess`, 76 seconds apart from the same identity, same IP, same session.

### 4. Coverage gaps identified

| Gap | Impact |
|---|---|
| `CreateUser` not in IAM filter | Target identity creation generated no alert |
| `PutBucketPolicy` not covered | S3 log-storage tampering undetected |
| No S3 data events enabled | Object-level access to the log bucket invisible |
| No correlation across events | Cannot express "StopLogging followed by StartLogging" as one rule |

### 5. Detection worked; response speed did not

All three scenarios were detected. But in the tampering case the trail was deleted at 06:12:03 while the responder had received one alert at 06:09:29 and no further signal. Detection latency was acceptable; **notification completeness was not**.

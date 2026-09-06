# MITRE ATT&CK Mapping

Techniques below were derived **after** evidence collection, from observed CloudTrail events. Each entry cites the specific `eventID` that supports it. No technique is listed without a corresponding event in the log.

Matrix: **ATT&CK for Enterprise — IaaS platform**
**Verified against attack.mitre.org on 2026-09-03.** Technique IDs, names, tactics, and platform applicability were confirmed against the live source; two corrections resulted (see Verification Notes at the end).
Account: 111122223333 · Region: us-east-1 (except where noted) · All times UTC

---

## Mapping table

| # | Time | Event | Tactic | Technique | eventID |
|---|---|---|---|---|---|
| 1 | 05:14:46 | `ConsoleLogin` (Root) | Initial Access | **T1078.004** — Valid Accounts: Cloud Accounts | `3aa8e2da` |
| 2 | 05:15–05:16 | Root viewed IAM, Billing | Discovery | **T1087.004** — Account Discovery: Cloud Account | *(readOnly events)* |
| 3 | 05:35:33 | `CreateUser` | Persistence | **T1136.003** — Create Account: Cloud Account | `80f8ece9` |
| 4 | 05:37:01 | `AttachUserPolicy` — ReadOnlyAccess | *(control case)* | T1098.003 — low confidence, see note | `aa8026e4` |
| 5 | 05:38:17 | `AttachUserPolicy` — IAMFullAccess | Privilege Escalation, Persistence | **T1098.003** — Account Manipulation: Additional Cloud Roles | `f235ea6b` |
| 6 | 05:40:05 | `CreateAccessKey` | Persistence | **T1098.001** — Account Manipulation: Additional Cloud Credentials | `7077c297` |
| 7 | 06:06:01 | `StopLogging` | Defense Impairment | **T1685.002** — Disable or Modify Tools: Disable or Modify Cloud Log | `3c596c6d` |
| 8 | 06:09:20 | `StartLogging` | Defense Impairment | **T1685.002** — see behavioural note | `34c51c39` |
| 9 | 06:10:21 | `UpdateTrail` | Defense Impairment | **T1685.002** | `44d038eb` |
| 10 | 06:10:21 | `PutBucketPolicy` | Defense Impairment | **T1685.002** — log storage layer | `5bfa1454` |
| 11 | 06:10:28 | `PutBucketPolicy` | Defense Impairment | **T1685.002** — log storage layer | `240b1b5e` |
| 12 | 06:10:29 | `UpdateTrail` | Defense Impairment | **T1685.002** | `622213b9` |
| 13 | 06:12:03 | `DeleteTrail` | Defense Impairment | **T1685.002** — Disable or Modify Cloud Log | `19580243` |

---

## Technique detail

### T1078.004 — Valid Accounts: Cloud Accounts

**Evidence:** `3aa8e2da` — `ConsoleLogin`, `userIdentity.type: "Root"`, `responseElements.ConsoleLogin: "Success"`, `additionalEventData.MFAUsed: "Yes"`, source `203.0.113.10`, recorded in **us-east-2**.

**Why it applies:** use of an existing legitimate credential rather than a created or stolen-and-forged one. The root account was authenticated normally, with MFA. Nothing in the event indicates compromise.

**Analytical note:** this technique is deliberately hard to detect from telemetry alone, because a valid login and a compromised login are byte-identical in the log. Detection relies on the account being *unexpected*, not on the event being malformed.

---

### T1087.004 — Account Discovery: Cloud Account

**Evidence:** read-only IAM console activity during the root session (05:15–05:16), captured as `readOnly: true` events.

**Why it applies:** enumerating identities and permissions is the standard precursor to escalation. In this simulation the activity was benign, but the log signature is identical to reconnaissance.

**Confidence: low.** These are read-only console events indistinguishable from ordinary administration. Listed for completeness, not as a detection candidate.

---

### T1136.003 — Create Account: Cloud Account

**Evidence:** `80f8ece9` — `CreateUser`, `requestParameters.userName: "test-analyst-user"`.

**Why it applies:** creation of a new identity to hold access independent of the original credential.

**Detection gap:** `CreateUser` was **not** in the IAM metric filter. This step generated no alert. First notification came 88 seconds later, at the policy attachment.

---

### T1098.003 — Account Manipulation: Additional Cloud Roles

**Evidence:** `f235ea6b` — `AttachUserPolicy`, `requestParameters.policyArn: "arn:aws:iam::aws:policy/IAMFullAccess"`.

**Control case:** `aa8026e4` — identical event 76 seconds earlier with `policyArn: ".../ReadOnlyAccess"`.

**Why it applies:** `IAMFullAccess` grants the ability to modify any IAM permission in the account, including self-elevation to `AdministratorAccess`. This is privilege escalation and persistence simultaneously — the identity gains power it did not have, and retains it beyond the current session.

**Why the pair matters:** the two events are identical in `eventName`, `userIdentity`, `sourceIPAddress`, `sessionContext`, and `userAgent`. Only `requestParameters.policyArn` differs. Technique assignment therefore depends on the *target* of the action, not the action itself.

Event 4 is not counted as a genuine instance of this technique. Attaching `ReadOnlyAccess` does not grant additional privilege in any meaningful sense; it is recorded here as the control case that established the distinction.

---

### T1098.001 — Account Manipulation: Additional Cloud Credentials

**Evidence:** `7077c297` — `CreateAccessKey` for `test-analyst-user`, key ID prefix `AKIA`.

**Why it applies:** a long-term programmatic credential provides access that survives console session expiry and is not subject to MFA. This is the persistence artifact.

**Analytical note:** the `AKIA` prefix is significant. An `ASIA` credential expires on its own; an `AKIA` credential does not. Containment for this event requires key deactivation, not session revocation.

---

### T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log

**Evidence:** `3c596c6d` (`StopLogging`), `34c51c39` (`StartLogging`), `44d038eb` and `622213b9` (`UpdateTrail`), `5bfa1454` and `240b1b5e` (`PutBucketPolicy`).

**Why it applies:** each event reduces or redirects audit visibility. `StopLogging` halts collection. `UpdateTrail` alters where logs are written. `PutBucketPolicy` modifies access controls on the log store itself.

**Behavioural note on `StartLogging` (`34c51c39`):** restarting a trail is benign in isolation and occurs routinely. Its significance here is positional — it follows `StopLogging` from the same identity, same session, three minutes and nineteen seconds later. The pattern creates a bounded gap in the record and then restores normal appearance.

This sequence is the technique instance. Neither event alone is.

**Scope note:** the two `PutBucketPolicy` events target the S3 log bucket rather than CloudTrail itself. They are mapped to T1685.002 because the effect is the same — impairing the integrity of cloud logging — but they fall outside the detection rule, which is scoped to `cloudtrail.amazonaws.com` event names only.

---

### T1685.002 — applied to trail deletion

**Evidence:** `19580243` — `DeleteTrail`, target `arn:aws:cloudtrail:us-east-1:111122223333:trail/secondary-trail`.

**Initial mapping was wrong.** This was first mapped to T1070 (Indicator Removal). Verification against attack.mitre.org showed T1070's platforms are Containers, ESXi, Linux, Network Devices, Office Suite, Windows, and macOS — **IaaS is not among them**. T1070 does not apply to AWS resources.

`DeleteTrail` therefore maps to T1685.002 alongside the other tampering events.

**Analytical note retained:** destruction differs operationally from impairment. A stopped trail can be restarted; a deleted one cannot. The technique is the same, but the response is not — recovery requires recreating the trail from scratch, and the configuration record of what was being collected is gone.

---

## Tactics observed

| Tactic | Techniques | Events |
|---|---|---|
| Initial Access / Stealth / Persistence / Privilege Escalation | T1078.004 | 1 |
| Discovery | T1087.004 | *(read-only, low confidence)* |
| Persistence | T1136.003, T1098.003, T1098.001 | 3 |
| Privilege Escalation | T1098.003 | 1 |
| Defense Impairment | T1685.002 | 7 |

Note that **T1098.003 appears under two tactics.** Attaching `IAMFullAccess` elevates privilege and establishes persistence in a single action. A single event can serve multiple tactical objectives.

---

## Tactics NOT observed

The simulation stopped after defense evasion. The following were deliberately not exercised:

| Tactic | Why absent |
|---|---|
| Credential Access | No secrets store or credential harvesting simulated |
| Lateral Movement | Single account, no cross-account role assumption |
| Collection | No data staged |
| Exfiltration | No data moved out of the account |
| Impact | No resources destroyed or encrypted; only the disposable trail was deleted |

Recording absent tactics matters: the attack chain here is incomplete by design. A real intrusion following this path would continue into Collection and Exfiltration, and this build has **no visibility into either** — S3 data events are disabled and no VPC Flow Logs exist (see Visibility Gaps 11.5).

---

## Unmapped observations

| Observation | Why not mapped |
|---|---|
| Failed root login attempts prior to 05:14:46 | Would map to T1110 (Brute Force) if adversarial, but these were operator error during testing. Mapping them would be dishonest. |
| ~669 read-only events in the window | Console page rendering and AWS-internal calls. Not attributable to any technique. |
| `LookupEvents` calls during investigation | Responder activity, not adversary activity. Must be excluded from any adversary timeline. |

---

## Method

Techniques were assigned in this order:

1. Attacks executed and evidence collected (Session 4)
2. Timeline reconstructed from CloudTrail with `readOnly: false` filter (Session 5)
3. Each observed event examined for what it actually accomplished
4. Technique selected to describe that effect, verified against attack.mitre.org
5. `eventID` recorded as supporting evidence

No technique was selected before the corresponding evidence existed. Where a mapping was ambiguous — `StartLogging`, `PutBucketPolicy`, `DeleteTrail` — the ambiguity is documented rather than resolved silently.


---

## Verification notes

All technique IDs were checked against attack.mitre.org on 2026-09-03. Two errors were found and corrected.

### Correction 1 — T1562.008 has been renumbered

| Was | Now |
|---|---|
| T1562.008 | **T1685.002** |
| Impair Defenses: Disable or Modify Cloud Logs | **Disable or Modify Tools: Disable or Modify Cloud Log** |
| Parent: T1562 | Parent: **T1685** |

Version 1.0, created 14 April 2026, last modified 12 May 2026. The old URL redirects, which is how the change was discovered.

### Correction 2 — T1070 does not apply to IaaS

`DeleteTrail` was initially mapped to T1070 (Indicator Removal). T1070's listed platforms are Containers, ESXi, Linux, Network Devices, Office Suite, Windows, and macOS. **IaaS is absent.** The mapping was invalid and was reassigned to T1685.002.

Platform applicability is not optional detail. A technique that does not list the relevant platform is the wrong technique, however well the description appears to fit.

### Tactic naming has changed

The tactic formerly called **Defense Evasion** no longer appears under that name in the version verified. It is now represented by:

- **Stealth** — T1078.004, T1070
- **Defense Impairment** — T1685.002

All references in this document use the current names.

### Verified technique reference

| Technique | ID | Tactic(s) | Platforms include IaaS | Version | Last modified |
|---|---|---|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Stealth, Persistence, Privilege Escalation, Initial Access | Yes | 2.0 | 12 May 2026 |
| Account Discovery: Cloud Account | T1087.004 | Discovery | Yes | 1.3 | 24 Oct 2025 |
| Create Account: Cloud Account | T1136.003 | Persistence | Yes | 1.6 | 24 Oct 2025 |
| Account Manipulation: Additional Cloud Credentials | T1098.001 | Persistence, Privilege Escalation | Yes | 2.8 | 24 Oct 2025 |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Persistence, Privilege Escalation | Yes | 2.5 | 24 Oct 2025 |
| Disable or Modify Tools: Disable or Modify Cloud Log | T1685.002 | Defense Impairment | Yes | 1.0 | 12 May 2026 |
| Indicator Removal | T1070 | Stealth | **No** — not applicable | 3.0 | 12 May 2026 |

Evidence: `26-mitre-technique-verified.png`

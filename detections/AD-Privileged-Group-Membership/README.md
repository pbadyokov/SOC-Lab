# Active Directory Privileged Group Membership Investigation

## Detection Summary

This lab investigates the creation of a test Active Directory account, its addition to Domain Admins, removal from the group, and subsequent deletion.

Windows Security events from DC01 were investigated in Splunk. PowerShell and Active Directory Users and Computers were used to validate account state and group membership.

The investigation identified:

- Event `4720` — User account creation.
- Event `4728` — Addition to a security-enabled global group.
- Event `4729` — Removal from a security-enabled global group.
- Event `4726` — User account deletion.

**Outcome:** All four event types were identified in Splunk for the test account. Privileged membership was removed and the account was deleted.

A temporary gap in event availability and an inconsistency between event timestamps were documented. Their underlying causes were not established.

This was a controlled administrative simulation. Events were correlated manually; no automated alert was implemented.

---

## Objective

The objective of this lab was to:

- Verify collection of domain controller Security logs.
- Check account and security group management auditing.
- Create a dedicated test account.
- Distinguish the actor from the affected account.
- Simulate and investigate a privileged group membership change.
- Correlate account activity using its SID.
- Verify membership removal and account deletion.
- Troubleshoot missing SIEM results using local evidence.
- Document findings without overstating what the logs prove.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Account Manipulation: Additional Local or Domain Groups | T1098.007 | Adding an account to a privileged domain group |

This mapping describes behavior that could be abused by an attacker. The change in this exercise was intentional and performed in a lab.

---

## Lab Environment

| Component | Role |
|---|---|
| Windows Server 2022 — DC01 | Domain Controller |
| CORP.LOCAL | Active Directory Domain |
| Windows 10 | Splunk Host |
| Active Directory Users and Computers | Account and Group Management |
| PowerShell | Audit, Account and Connectivity Checks |
| Splunk Universal Forwarder | Log Forwarding |
| Splunk Enterprise | Security Event Investigation |

Network configuration:

```text
DC01:
192.168.56.10

Splunk Host:
192.168.56.110

Splunk Receiving Port:
9997
```

Test account:

```text
Logon Name:
soclab-test

Display Name:
SOC Lab Test

Distinguished Name:
CN=SOC Lab Test,CN=Users,DC=CORP,DC=LOCAL

SID:
S-1-5-21-3788158350-455610885-851012159-1129
```

Target group:

```text
Group:
CORP\Domain Admins

SID:
S-1-5-21-3788158350-455610885-851012159-512
```

---

## Attack Overview

An unexpected addition to Domain Admins can give an account extensive administrative authority within the domain.

The change requires investigation even when the actor is an administrator. The administrator account could be compromised, or the action could lack approval.

The controlled sequence was:

1. Create a test account.
2. Verify its identity and current state.
3. Add it to Domain Admins.
4. Investigate the addition.
5. Remove the privileged membership.
6. Investigate the removal.
7. Delete the account and identify the deletion event.

The test account was not used to sign in during this exercise.

---

## Lab Configuration

### Verify Security Log Collection

```spl
index=* host="DC01*" source="*WinEventLog:Security"
| stats count by host source
```

Security events from DC01 were available in Splunk before the simulation.

### Verify Audit Settings

The following commands were executed on DC01:

```powershell
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Security Group Management"
```

Both subcategories showed:

```text
Success
```

No audit policy change was required.

| Audit Subcategory | Relevant Events |
|---|---|
| User Account Management | 4720, 4726 |
| Security Group Management | 4728, 4729 |

Domain Admins is a security-enabled global group.

---

## Attack Execution

### Create the Test Account

Active Directory Users and Computers was opened using:

```text
dsa.msc
```

The account was created in the standard Users container:

```text
Full Name:
SOC Lab Test

User Logon Name:
soclab-test
```

A lab-only password was configured, and the requirement to change the password at the next sign-in was cleared.

Initial attempts encountered password policy rejection. Account creation completed after a different password was selected.

Passwords are excluded from this documentation.

### Verify Account State

```powershell
Get-ADUser -Identity "soclab-test" -Properties PasswordLastSet |
Select-Object SamAccountName, Enabled, PasswordLastSet, SID
```

Observed:

```text
SamAccountName:
soclab-test

Enabled:
True

PasswordLastSet:
2026-10-08 16:53:16

SID:
S-1-5-21-3788158350-455610885-851012159-1129
```

The SID matched the final account creation event.

### Add the Account to Domain Admins

In Active Directory Users and Computers:

1. Open SOC Lab Test properties.
2. Select Member Of.
3. Select Add.
4. Enter Domain Admins.
5. Select Check Names.
6. Apply the change.

Event `4728` was identified in Splunk.

### Remove the Membership

In the same Member Of tab:

1. Select Domain Admins.
2. Select Remove.
3. Apply the change.
4. Reopen account properties to verify its absence.

The removal was verified in Active Directory. Event `4729` was initially found locally on DC01 and later in Splunk.

### Delete the Test Account

The dedicated SOC Lab Test account was deleted through Active Directory Users and Computers.

Event `4726` was subsequently identified in Splunk with the same account SID.

---

## Evidence Collected

### Event 4720 — Account Creation

Observed:

```text
Displayed Timestamp:
2026-10-08 16:53:16.599

ComputerName:
DC01.CORP.LOCAL

RecordNumber:
22952

Subject Account:
CORP\Administrator

New Account:
CORP\soclab-test

New Account SID:
S-1-5-21-3788158350-455610885-851012159-1129
```

The Subject section identified the actor. The New Account section identified the created account.

At creation time, the event showed:

```text
Account Disabled

Password Last Set:
<never>
```

The later PowerShell check showed `Enabled=True` and a populated password timestamp.

These observations describe different points in the account lifecycle. The creation event did not independently establish the final account state.

### Event 4728 — Addition to Domain Admins

Observed:

```text
Displayed Timestamp:
2026-10-08 17:29:23.393

RecordNumber:
23304

Subject Account:
CORP\Administrator

Subject Logon ID:
0x68752

Member:
CN=SOC Lab Test,CN=Users,DC=CORP,DC=LOCAL

Member SID:
S-1-5-21-3788158350-455610885-851012159-1129

Group:
CORP\Domain Admins

Group SID:
S-1-5-21-3788158350-455610885-851012159-512
```

The sections had distinct roles:

| Section | Meaning |
|---|---|
| Subject | Account performing the change |
| Member | Account added to the group |
| Group | Group receiving the new member |

This event confirmed the addition. It did not independently establish approval or the identity of the person operating the administrator account.

### Event 4729 — Removal from Domain Admins

Observed:

```text
Displayed Timestamp:
2026-10-08 17:15:54.936

RecordNumber:
23377

Subject Account:
CORP\Administrator

Subject Logon ID:
0x68752

Member:
CN=SOC Lab Test,CN=Users,DC=CORP,DC=LOCAL

Member SID:
S-1-5-21-3788158350-455610885-851012159-1129

Group:
CORP\Domain Admins

Group SID:
S-1-5-21-3788158350-455610885-851012159-512
```

The member and group SIDs matched the addition event.

The event was first verified locally and later retrieved in Splunk.

Its displayed timestamp precedes the addition timestamp despite its higher record number. This inconsistency is retained and discussed in the timeline section.

### Event 4726 — Account Deletion

Observed:

```text
Displayed Timestamp:
2026-10-08 17:57:32.829

RecordNumber:
23828

Subject Account:
CORP\Administrator

Subject Logon ID:
0x5B819

Target Account:
CORP\soclab-test

Target Account SID:
S-1-5-21-3788158350-455610885-851012159-1129
```

The target SID matched the account in the creation and membership events.

The Subject Logon ID differed from the earlier events. The deletion should therefore not be described as occurring in the same logon session solely because the account name was unchanged.

---

## Splunk Detection

The searches below reproduce the lab investigation. For historical review, select a time range covering October 8, 2026.

### Find Account Creation

```spl
index=* host="DC01*" EventCode=4720 "soclab-test"
```

Review the Subject and New Account sections to distinguish the actor from the created account.

### Compare Creation Record Numbers

Seven creation events appeared during the repeated setup attempts.

RecordNumber was visible in the raw event but initially unavailable as an extracted field in the search. It was extracted explicitly:

```spl
index=* host="DC01*" EventCode=4720 "soclab-test"
| rex field=_raw "RecordNumber=(?<RecordNumberExtracted>\d+)"
| table _time host RecordNumberExtracted source
| sort _time
```

The results showed different timestamps and record numbers.

These were distinct source records, not seven copies of a single event. They did not establish that seven accounts still existed.

The earlier create/delete sequences were not fully reconstructed. The final account was identified using its SID.

### Detect Additions to Domain Admins

```spl
index=* host="DC01*" EventCode=4728 "Domain Admins"
```

Inspect Subject, Member and Group.

The retained screenshot used the broader query:

```spl
index=* host="DC01*" EventCode=4728
```

It returned the relevant Domain Admins addition.

### Detect Removal from Domain Admins

```spl
index=* host="DC01*" EventCode=4729 "Domain Admins"
```

During troubleshooting, the search was broadened to:

```spl
index=* EventCode=4729
```

The removal event was subsequently found in Splunk.

### Find Account Deletion

```spl
index=* host="DC01*" EventCode=4726 "soclab-test"
```

Verify the affected account under Target Account, including its SID.

### Follow-up Search by Account SID

The following query can be used to retrieve the four event types without relying on the account's changing name representation:

```spl
index=* host="DC01*" source="*WinEventLog:Security"
(EventCode=4720 OR EventCode=4728 OR EventCode=4729 OR EventCode=4726)
"S-1-5-21-3788158350-455610885-851012159-1129"
| rex field=_raw "RecordNumber=(?<RecordNumberExtracted>\d+)"
| eval RecordNumberExtracted=tonumber(RecordNumberExtracted)
| sort 0 RecordNumberExtracted
| table _time host EventCode RecordNumberExtracted Message
```

This is a follow-up investigation query; it is not shown in the retained screenshots.

Ordering by record number is useful here because these records belong to the same host and Security log. Record numbers should not be treated as a global ordering mechanism across hosts, channels or log resets.

For production use, replace `index=*` with the intended index and validate field extractions.

---

## Detection Logic

| Stage | Evidence | Conclusion |
|---|---|---|
| Account creation | 4720 | Administrator created the account with the recorded SID |
| State validation | Get-ADUser | The account was enabled and had a password set |
| Privileged membership addition | 4728 | The account was added to Domain Admins |
| Privileged membership removal | 4729 and membership check | The account was removed from Domain Admins |
| Account deletion | 4726 | The same account was deleted |

The full account SID connected:

- New Account in Event `4720`.
- Member in Events `4728` and `4729`.
- Target Account in Event `4726`.

The group SID connected the addition and removal to the same Domain Admins group.

No automated cross-event correlation rule was implemented.

---

## Detection Workflow

1. Verify Security log collection from DC01.
2. Check the required audit subcategories.
3. Locate the account creation event.
4. Identify the actor and record the new account SID.
5. Validate current account state.
6. Locate the privileged group addition.
7. Identify the actor, member and group.
8. Assess approval and administrative session context.
9. Remove membership and locate the removal event.
10. Delete the test account and locate the deletion event.
11. Compare identifiers, record order and timestamps.
12. Document evidence gaps and unresolved inconsistencies.

### Recorded Event Sequence

The table is ordered by record number within DC01's Security log:

| Record Number | Displayed Timestamp | Event ID | Activity |
|---|---|---|---|
| 22952 | 2026-10-08 16:53:16.599 | 4720 | Account created |
| 23304 | 2026-10-08 17:29:23.393 | 4728 | Account added to Domain Admins |
| 23377 | 2026-10-08 17:15:54.936 | 4729 | Account removed from Domain Admins |
| 23828 | 2026-10-08 17:57:32.829 | 4726 | Account deleted |

### Timestamp Inconsistency

The removal event displays a time earlier than the addition event, although its record number is higher and the controlled exercise performed removal after addition.

The screenshots show this inconsistency in the event text as well as the displayed Splunk time.

The cause was not established. A clock adjustment is a possible explanation, but it was not verified.

Consequently:

- The original displayed timestamps are preserved.
- The membership duration is not calculated.
- Event record order and the observed lab sequence are documented separately from wall-clock time.
- Sorting only by `_time` would produce a misleading sequence for this evidence set.

The screenshots do not expose an explicit UTC offset. Times have not been independently normalized to UTC.

---

## Telemetry Troubleshooting

Event `4729` was initially absent from Splunk searches even though the membership had been removed.

### Verify Local Event Generation

On DC01:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4729
    StartTime = (Get-Date).AddHours(-1)
} | Format-List TimeCreated, Message
```

The removal event was present locally.

This established that the action had been audited on the source host.

### Check Event Freshness

```spl
index=* host="DC01*" source="*WinEventLog:Security"
| stats max(_time) as latest_event max(_indextime) as latest_received
| convert ctime(latest_event) ctime(latest_received)
```

At approximately 17:45, the search showed:

```text
Latest event time:
17:29

Latest indexing time:
17:33
```

These maxima may belong to different records. Their difference does not establish an individual event's forwarding delay.

### Check the Forwarder Service

```powershell
Get-Service SplunkForwarder
```

Observed:

```text
Running
```

### Check Receiver Connectivity

```powershell
Test-NetConnection 192.168.56.110 -Port 9997
```

Observed:

```text
TcpTestSucceeded:
True
```

A running service and reachable TCP port did not independently prove successful event delivery or indexing.

### Resolution Status

The removal event was subsequently retrieved in Splunk, and the deletion event was also available.

The collection issue's root cause was not established. No event-specific filter or configuration defect was confirmed.

The evidence does not establish that a restart fixed the issue, or that the timestamp inconsistency caused the temporary search gap.

---

## False Positives and Limitations

Legitimate administrative work can generate the same account and group management events.

An administrator account in the Subject section does not automatically make the action legitimate.

A real investigation should check:

- An approved change request.
- The business need for privileged access.
- Confirmation through a trusted channel.
- The administrative session's origin.
- Related suspicious activity before and after the change.

Limitations:

- This was a controlled simulation, not a confirmed compromise.
- Earlier creation attempts were not fully reconstructed.
- No use of the granted privileges was demonstrated.
- Event timestamp inconsistency prevents a reliable membership-duration calculation.
- The temporary SIEM availability gap was not fully diagnosed.
- No logon-event correlation was completed.
- Screenshots represent selected evidence rather than a complete exported event set.

Removing membership does not establish that all previously issued sessions or access tokens have immediately lost their privileges.

---

## Mitigation

Possible defensive measures include:

- Require approval for privileged group membership changes.
- Minimize standing Domain Admins membership.
- Separate administrative accounts from everyday accounts.
- Monitor both membership additions and removals.
- Investigate short-lived privileged memberships.
- Correlate changes with administrative logons and surrounding activity.
- Monitor collection freshness and clock consistency.
- Preserve evidence before remediation.
- Verify membership removal and account cleanup.

---

## Cleanup

Cleanup was completed in two stages.

### Remove Privileged Membership

SOC Lab Test was removed from Domain Admins through its Member Of settings.

The absence of the membership was checked in Active Directory.

Event `4729`, RecordNumber `23377`, confirmed removal and was retrieved in Splunk.

### Delete the Test Account

The dedicated test account was deleted.

Event `4726`, RecordNumber `23828`, recorded:

```text
Target Account:
CORP\soclab-test

Target SID:
S-1-5-21-3788158350-455610885-851012159-1129
```

The matching SID confirmed deletion of the account used in the exercise.

Historical Security logs and Splunk events were retained for analysis.

---

## Screenshots

All seven screenshots are stored in the same directory as this README.

### 01 — Audit Policy Verification

Successful auditing enabled for User Account Management and Security Group Management.

![Audit policy verification](01-dc01-auditpol-check.png)

### 02 — Test Account in Active Directory

SOC Lab Test visible in the standard Users container.

![Test account in Active Directory](02-dc01-new-acc-creation.png)

### 03 — Account State and SID Verification

PowerShell output showing the account enabled, its password timestamp and SID.

![Account state verification](03-dc01-newacc-check.png)

### 04 — Event 4720: Account Creation

Security event identifying the creating administrator and the new account.

![Account creation event](04-splunk-newacc-discovery.png)

### 05 — Event 4728: Addition to Domain Admins

Security event showing the actor, added member and privileged group.

![Domain Admins membership addition](05-splunk-4728-event.png)

### 06 — Event 4729: Removal from Domain Admins

Removal event retrieved in Splunk with the same member and group SIDs.

The displayed timestamp inconsistency is discussed in the timeline section.

![Domain Admins membership removal](06-splunk-4729-event.png)

### 07 — Event 4726: Account Deletion

Deletion event identifying the same test account by SID.

![Test account deletion](07-splunk-4726-account-deletion.png)

---

## Lessons Learned

This exercise demonstrated how to investigate a privileged group membership change while distinguishing the actor, member and group.

The account SID connected creation, membership changes and deletion even though the account appeared under different name formats.

The creation event and later PowerShell output showed why event-time state should be separated from current account state.

The temporary absence of the removal event in Splunk demonstrated the importance of checking local evidence before concluding that an action was not logged.

Finally, the timestamp inconsistency showed why a timeline should not be built blindly from displayed times. Record order, account identifiers, clock consistency and the limits of the available evidence all matter.

# PsExec Lateral Movement Detection

## Detection Summary

This detection identifies lateral movement performed through SMB administrative shares and remote Windows service execution using Impacket PsExec.

The attack was detected by correlating Windows authentication events, administrative share access, service creation, and Sysmon process creation telemetry in Splunk.

---

## Objective

The objective of this lab was to:

- Simulate lateral movement using Impacket PsExec.
- Authenticate remotely using a privileged domain account.
- Identify SMB administrative share activity.
- Detect the executable transferred through `ADMIN$`.
- Detect remote Windows service creation.
- Correlate the service executable with Sysmon process execution.
- Reconstruct the complete attack timeline in Splunk.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Remote Services: SMB/Windows Admin Shares | T1021.002 |
| System Services: Service Execution | T1569.002 |

---

## Lab Environment

| Machine | Role |
|---|---|
| Kali Linux | Attacker |
| Windows 10 | Target Workstation |
| Windows Server 2022 | Domain Controller |
| Splunk Enterprise | SIEM |

Additional telemetry:

- Windows Security Logs
- Windows System Logs
- Sysmon
- Splunk Universal Forwarder

Domain:

```text
CORP.LOCAL
```

---

## Attack Overview

PsExec can be used for lateral movement by authenticating to a remote Windows system over SMB and accessing administrative shares.

Impacket PsExec performs several actions on the target:

1. Authenticates to the target over SMB.
2. Connects to the `ADMIN$` administrative share.
3. Uploads a temporary executable.
4. Creates a temporary Windows service.
5. Starts the service.
6. Executes the uploaded binary as `NT AUTHORITY\SYSTEM`.
7. Provides a remote command shell.

This creates telemetry across several Windows log sources that can be correlated to identify the activity.

---

## Lab Configuration

The Windows 10 workstation was joined to the `CORP.LOCAL` Active Directory domain.

A privileged domain account was used to perform the remote administration activity.

SMB was enabled on the target by enabling the Windows File and Printer Sharing firewall rules.

To collect SMB share telemetry, the following Advanced Audit Policy settings were enabled:

```text
Object Access
├── Audit File Share
└── Audit Detailed File Share
```

Success auditing was enabled for both policies.

The policy was applied using:

```cmd
gpupdate /force
```

This allowed Windows to generate Event IDs `5140` and `5145` during the attack.

---

## Attack Execution

The attack was executed from Kali Linux using Impacket PsExec:

```bash
impacket-psexec CORP.LOCAL/socadmin:'<REDACTED>'@<TARGET-IP>
```

Successful execution resulted in a remote command shell on the Windows 10 workstation.

The remote process executed with:

```text
NT AUTHORITY\SYSTEM
```

---

## Evidence Collected

Several events were generated during the PsExec execution.

### Event ID 4624 — Successful Network Logon

A successful network authentication was observed for:

```text
Account Name: socadmin
Logon Type: 3
```

Logon Type `3` represents a network logon and is consistent with remote SMB authentication.

---

### Event ID 5140 — Network Share Access

Windows recorded access to the administrative share:

```text
Account Name: socadmin
Share Name: \\*\ADMIN$
```

This indicates that the privileged account accessed the target's administrative SMB share.

---

### Event ID 5145 — Detailed File Share Access

Detailed File Share auditing revealed the executable accessed through the administrative share:

```text
Account Name: socadmin
Share Name: \\*\ADMIN$
Relative Target Name: DzEwAwZT.exe
```

The random executable name became an important correlation point during the investigation.

---

### Event ID 7045 — Service Installation

Windows Service Control Manager recorded a new service:

```text
Service Name: qWQj
Service File Name: %systemroot%\DzEwAwZT.exe
Service Type: user mode service
Service Start Type: demand start
Service Account: LocalSystem
```

The executable recorded in Event ID `7045` matches the executable observed through `ADMIN$` in Event ID `5145`.

---

### Sysmon Event ID 1 — Process Creation

Sysmon recorded execution of the same executable:

```text
Image:
C:\Windows\DzEwAwZT.exe

ParentImage:
C:\Windows\System32\services.exe

CommandLine:
C:\Windows\DzEwAwZT.exe

User:
NT AUTHORITY\SYSTEM
```

This confirmed that the uploaded executable was launched by the Windows Service Control Manager and executed with SYSTEM privileges.

---

## Splunk Detection

### Detect Network Authentication

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=4624 Account_Name="socadmin"
```

Look for:

```text
Logon_Type=3
```

---

### Detect Administrative Share Access

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=5140
```

Look for access to:

```text
ADMIN$
C$
IPC$
```

---

### Detect Detailed Share Access

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=5145
```

Important fields include:

```text
Account_Name
Share_Name
Relative_Target_Name
Source_Address
```

---

### Detect Service Creation

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=7045
```

Look for:

- Unusual service names
- Executables in suspicious locations
- Randomly named executables
- Services running as `LocalSystem`

---

### Detect Process Execution

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=1 Image="C:\\Windows\\DzEwAwZT.exe"
| table _time Image ParentImage CommandLine User
```

The observed process relationship was:

```text
services.exe
    ↓
DzEwAwZT.exe
    ↓
NT AUTHORITY\SYSTEM
```

---

## Detection Logic

PsExec activity becomes significantly more suspicious when multiple events are correlated within a short time window.

The observed attack produced:

```text
SMB Authentication
        ↓
4624 — Logon Type 3
        ↓
5140 — ADMIN$ Share Access
        ↓
5145 — DzEwAwZT.exe
        ↓
7045 — Service qWQj Created
        ↓
Sysmon Event 1
        ↓
services.exe → DzEwAwZT.exe
        ↓
NT AUTHORITY\SYSTEM
```

A particularly strong indicator was the correlation of the same executable across multiple telemetry sources:

```text
Event 5145
ADMIN$\DzEwAwZT.exe

        ↓

Event 7045
%systemroot%\DzEwAwZT.exe

        ↓

Sysmon Event 1
C:\Windows\DzEwAwZT.exe
```

This connects SMB file access directly to service creation and SYSTEM-level process execution.

---

## Detection Workflow

1. Identify successful network authentication using Event ID `4624`.
2. Confirm Logon Type `3`.
3. Search for administrative share access using Event ID `5140`.
4. Examine Event ID `5145` for files accessed through `ADMIN$`.
5. Identify newly installed services using Event ID `7045`.
6. Compare the service executable with the file observed in Event ID `5145`.
7. Search Sysmon Event ID `1` for execution of the same binary.
8. Examine the parent process and execution account.
9. Correlate all events by hostname and timestamp.

Observed timeline:

| Timestamp | Event | Activity |
|---|---|---|
| 13:23:19.748 | 5140 | `socadmin` accessed `ADMIN$` |
| 13:23:19.752 | 5145 | `DzEwAwZT.exe` accessed through `ADMIN$` |
| 13:23:19.792 | 7045 | Service `qWQj` created |
| 13:23:19.805 | Sysmon 1 | `DzEwAwZT.exe` executed as SYSTEM |
| 13:23:19.909 | 4624 | Additional Type 3 network logon activity |

---

## Mitigation

Possible defensive measures include:

- Restrict access to administrative shares.
- Limit local and domain administrator privileges.
- Use separate privileged administrative accounts.
- Restrict SMB traffic between workstations.
- Monitor remote service creation.
- Enable File Share and Detailed File Share auditing.
- Deploy endpoint protection capable of detecting remote service execution.
- Monitor `services.exe` spawning unusual executables.
- Apply network segmentation to reduce lateral movement opportunities.

---

## Screenshots

### PsExec Execution

Successful remote command execution using Impacket PsExec.

```text
screenshots/01-psexec-shell.png
```

### Authentication and Service Creation

Correlation between network authentication and service installation.

```text
screenshots/02-splunk-correlating-events.png
```

### SMB Administrative Share Activity

Event IDs `5140` and `5145` showing `ADMIN$` access and the temporary executable.

```text
screenshots/03-smb-shares-telemetry-splunk.png
```

### Sysmon Process Execution

Sysmon Event ID `1` showing the temporary executable launched by `services.exe` as SYSTEM.

```text
screenshots/04-sysmon-process-execution.png
```

---

## Lessons Learned

This lab demonstrated how PsExec-style lateral movement can be reconstructed by correlating multiple Windows telemetry sources.

The most important finding was that no single event provided the complete picture.

Event ID `5145` identified the executable transferred through `ADMIN$`, Event ID `7045` showed the same executable being installed as a Windows service, and Sysmon Event ID `1` confirmed that the executable was launched by `services.exe` under `NT AUTHORITY\SYSTEM`.

The lab also demonstrated the importance of proper audit configuration. File Share and Detailed File Share auditing had to be enabled before Events `5140` and `5145` became available.

Correlating authentication, SMB activity, service creation, and process execution provided much stronger evidence of lateral movement than relying on any individual event.

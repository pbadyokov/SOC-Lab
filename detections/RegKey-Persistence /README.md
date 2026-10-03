# Registry Run Key Persistence Detection

## Detection Summary

This detection identifies potential persistence established through modifications to Windows Registry Run keys.

The activity was investigated using Sysmon Event ID `13`, which recorded the Registry value modification, and Event ID `1`, which recorded the subsequent execution of the configured program.

A harmless Notepad executable was used to simulate automatic execution at user sign-in.

---

## Objective

The objective of this lab was to:

- Simulate persistence using a Registry Run key.
- Create a startup entry for the current user using `reg.exe`.
- Detect the Registry modification through Sysmon telemetry.
- Identify the process responsible for modifying the Registry.
- Verify automatic execution after user sign-in.
- Investigate the resulting process creation event in Splunk.
- Search for Run key modifications independently of the test value name.
- Remove the persistence entry and verify cleanup.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |

---

## Lab Environment

| Component | Role |
|---|---|
| Windows 10 | Target Workstation |
| Sysmon | Endpoint Telemetry |
| Splunk Universal Forwarder | Log Forwarding |
| Splunk Enterprise | SIEM |

User account:

```text
CORP\socadmin
```

Persistence location:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Test executable:

```text
C:\Windows\System32\notepad.exe
```

---

## Attack Overview

Windows Registry Run keys allow programs to execute automatically when a user signs in.

These keys are commonly used by legitimate applications but can also be abused to establish persistence.

An attacker can configure a Run value to launch an executable or command during subsequent sign-ins.

In this lab, a value named:

```text
SOC-Lab-Notepad
```

was created under the current user's Run key.

The value pointed to:

```text
C:\Windows\System32\notepad.exe
```

Notepad was used as a harmless substitute for a malicious payload.

The entry applied to the current user and did not configure execution under `SYSTEM`.

---

## Lab Configuration

Sysmon telemetry was already being collected in Splunk.

The investigation used:

| Event ID | Purpose |
|---|---|
| 13 | Registry Value Set |
| 1 | Process Creation |

The Sysmon configuration recorded the relevant Registry modification and process execution events.

No additional Windows Security audit policy changes were required for this exercise.

---

## Attack Execution

The Run value was created from PowerShell using:

```powershell
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SOC-Lab-Notepad" /t REG_SZ /d "C:\Windows\System32\notepad.exe"
```

The entry was configured with:

```text
Registry Key:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Value Name:
SOC-Lab-Notepad

Value Type:
REG_SZ

Value Data:
C:\Windows\System32\notepad.exe
```

Windows confirmed successful execution of the command.

The value was verified using:

```powershell
reg.exe query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SOC-Lab-Notepad"
```

The returned data confirmed the correct executable path.

On the following day, Notepad opened automatically when the same user signed in.

---

## Evidence Collected

Two important Sysmon events were identified during the investigation.

### Event ID 13 — Registry Value Set

Sysmon recorded the modification of the Run value.

Observed:

```text
EventCode:
13

EventType:
SetValue

Image:
C:\Windows\system32\reg.exe

TargetObject:
HKU\<User SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOC-Lab-Notepad

Details:
C:\Windows\System32\notepad.exe

User:
CORP\socadmin
```

The `Image` field identified the process responsible for modifying the Registry.

The `TargetObject` field identified the persistence location and value name.

The `Details` field contained the program configured to execute at sign-in.

Sysmon represented the current user's Registry hive as:

```text
HKU\<User SID>
```

This corresponds to the user-specific hive accessed through `HKCU` in the command.

Event ID `13` confirmed that the startup value was set. It did not independently prove execution of the configured program.

---

### Event ID 1 — Process Creation

After the subsequent sign-in, Sysmon recorded the execution of Notepad.

Observed:

```text
Image:
C:\Windows\System32\notepad.exe

ParentImage:
C:\Windows\explorer.exe

User:
CORP\socadmin

CommandLine:
"C:\Windows\System32\notepad.exe"
```

The process creation event confirmed execution of the program referenced by the Run value.

The parent process was:

```text
C:\Windows\explorer.exe
```

This was consistent with the observed automatic launch during sign-in.

However, an `explorer.exe` parent alone does not prove Run key execution because it can also appear during manual application launches.

The conclusion was supported by the controlled test, the Registry configuration, and the observation that Notepad opened automatically.

---

## Splunk Detection

### Detect the Lab Run Value Modification

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=13 "SOC-Lab-Notepad"
| sort - _time
```

This search identifies events containing the known test value name.

Important fields include:

```text
Image
TargetObject
Details
User
ProcessGuid
```

Analysts should review the process responsible for the modification and the configured startup command.

---

### Detect General Run Key Modifications

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=13
TargetObject="*\\CurrentVersion\\Run*"
| table _time host Image TargetObject Details
| sort - _time
```

This search identifies Registry value modifications without depending on the name `SOC-Lab-Notepad` or the Notepad executable.

The `Run*` pattern is broad and can also match paths such as `RunOnce`.

The search returned both the lab entry and Microsoft Edge startup entries.

This demonstrated that Run key modifications can result from legitimate application activity.

For production use, scope the search to the appropriate Sysmon source and index, define the intended Registry paths, and tune against expected software behavior.

---

### Identify Execution of the Configured Program

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=1
Image="*notepad.exe*"
| table _time Image ParentImage User CommandLine
| sort - _time
```

This search was used to investigate execution of the program identified in the Registry event.

Important fields include:

```text
Image
ParentImage
User
CommandLine
```

The search is a follow-up investigation query for this lab. Notepad execution alone is not an indicator of malicious activity.

The extracted `User` column included both `NOT_TRANSLATED` and `CORP\socadmin`. Windows event metadata should be distinguished from the execution user recorded inside the Sysmon message.

---

## Detection Logic

The investigation connected the persistence configuration with subsequent process execution.

| Stage | Evidence |
|---|---|
| Configure automatic execution | Event ID `13` recorded `reg.exe` setting the Run value |
| Identify the configured program | `Details` contained the Notepad executable path |
| Verify execution | Event ID `1` recorded the matching executable |
| Review execution context | The process ran as `CORP\socadmin` with `explorer.exe` as its parent |

Event ID `13` provided visibility into the Registry modification.

Event ID `1` provided visibility into the program's execution.

Together with the observed automatic launch, these events supported successful persistence in the controlled lab.

The events were compared manually. No automated correlation rule was implemented.

---

## Detection Workflow

1. Search for Event ID `13` involving Registry Run paths.
2. Review the modified Registry value.
3. Identify the process responsible for the change.
4. Review the user recorded in the Sysmon message.
5. Extract the configured executable or command from `Details`.
6. Search Event ID `1` for execution of that program.
7. Compare the host, user, command line and timestamps.
8. Review the parent process and sign-in context.
9. Determine whether the startup configuration is expected.
10. Remove the lab value after completing validation.

Observed timeline:

| Timestamp | Event | Activity |
|---|---|---|
| 2026-10-02 15:59:15.866 | 13 | `reg.exe` set the Run value to the correct Notepad path |
| 2026-10-03 16:40:02.289 | 1 | Notepad executed after the user signed in |
| After validation | Command output | The test value was deleted and its absence verified |

Timestamps above use the local time displayed in Splunk, UTC+03:00.

The persistence value remained between sign-ins, allowing the configured program to execute on the following day.

---

## False Positives and Limitations

Registry Run keys are also used by legitimate software.

Expected activity may include:

- Application installation.
- Software updates.
- Changes to startup preferences.
- Approved administrative configuration.

A matching Registry event should be investigated before being classified as malicious.

Potentially suspicious findings include unexpected executables, unusual command-line arguments, untrusted files, or changes made by an unfamiliar process.

Detection depends on the Sysmon configuration, successful log forwarding, correct field extraction and a suitable search time range.

An earlier test used the incorrect path:

```text
C:\Windows\System\notepad.exe
```

The path was corrected to:

```text
C:\Windows\System32\notepad.exe
```

Historical events from the incorrect attempt remained visible in Splunk. The successful test was documented using the event containing the correct path.

---

## Mitigation

Possible defensive measures include:

- Monitor changes to Registry Run and RunOnce locations.
- Collect relevant Registry and process creation telemetry.
- Investigate unexpected startup commands.
- Review executables launched from unusual or user-writable directories.
- Validate file origin, signatures and hashes during investigation.
- Use application control to restrict unauthorized execution.
- Remove unauthorized startup values after investigation.

Standard users can configure startup entries in their own `HKCU` hive. Restricting administrative privileges alone does not prevent this per-user persistence mechanism.

---

## Cleanup

The test value was removed using:

```powershell
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SOC-Lab-Notepad" /f
```

Windows confirmed successful deletion.

The removal was verified using:

```powershell
reg.exe query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SOC-Lab-Notepad"
```

Result:

```text
ERROR: The system was unable to find the specified registry key or value.
```

This was the expected response and confirmed that the test value no longer existed.

Only the lab value was deleted. Historical Splunk events remained available for analysis.

Deleting the value does not terminate an already running Notepad process.

---

## Screenshots

### Registry Run Value Creation

Creation and verification of the startup value pointing to Notepad.

![Registry Run value creation](<regkey-creation(1).png>)

### Event ID 13 — Registry Value Set

Sysmon telemetry showing the process, user, Registry location and configured executable.

![Registry value modification event](splunk-regkey-registration-event.png)

### General Run Key Detection

Splunk search showing the lab entry alongside other startup modifications.

![General Run key detection](splunk-regkey-reg.png)

*The highlighted image is an AI-edited illustration. The original Event ID 13 screenshot above is the authoritative evidence for the Registry event.*

### Event ID 1 — Process Creation

Splunk telemetry showing Notepad executing under `CORP\socadmin` with `explorer.exe` as its parent.

![Notepad process creation](<splunk-notepad-finding(1).png>)

### Registry Value Removal

Successful deletion of the test value and verification that it no longer existed.

![Registry value cleanup](regkey-deletion.png)

---

## Lessons Learned

This lab demonstrated how a per-user Registry Run value can establish persistence and how the activity can be investigated using Sysmon and Splunk.

Event ID `13` identified the process responsible for setting the value and the program configured for automatic execution.

Event ID `1` confirmed that the program subsequently executed and exposed its user, parent process and command line.

The exercise highlighted the distinction between configuring persistence and observing execution. It also demonstrated that legitimate applications generate similar startup modifications, making context essential during investigation.

Finally, the incorrect initial executable path showed why detecting a Registry modification does not necessarily mean the configured program can run successfully.

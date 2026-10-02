# PowerShell Execution Detection

## Detection Summary

This detection identifies potentially suspicious PowerShell execution using Windows Process Creation telemetry and PowerShell Script Block Logging.

The activity was detected by correlating Windows Security Event ID `4688`, which recorded the PowerShell process and command-line arguments, with PowerShell Operational Event ID `4104`, which recorded executed PowerShell script blocks.

The lab focused on PowerShell executions using options such as:

```text
-NoProfile
-ExecutionPolicy Bypass
-EncodedCommand
```

These arguments are not inherently malicious, but their use can provide valuable behavioral indicators during an investigation.

---

## Objective

The objective of this lab was to:

- Enable PowerShell Script Block Logging.
- Forward PowerShell Operational logs to Splunk.
- Generate benign PowerShell activity using suspicious execution arguments.
- Execute a Base64-encoded PowerShell command.
- Detect PowerShell process creation using Event ID `4688`.
- Analyze executed PowerShell content using Event ID `4104`.
- Identify suspicious PowerShell command-line arguments.
- Correlate process creation and script block telemetry in Splunk.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 |

---

## Lab Environment

| Machine | Role |
|---|---|
| Windows 10 | Target Workstation |
| Windows Server 2022 | Domain Controller |
| Splunk Enterprise | SIEM |

Additional telemetry:

- Windows Security Logs
- PowerShell Operational Logs
- PowerShell Script Block Logging
- Splunk Universal Forwarder

Domain:

```text
CORP.LOCAL
```

---

## Attack Overview

PowerShell is a legitimate Windows administration and automation framework.

Its extensive access to Windows APIs, the filesystem, registry, network functionality, and .NET makes it useful for administrators but also attractive for attackers.

Suspicious PowerShell execution may involve arguments such as:

```text
-NoProfile
-ExecutionPolicy Bypass
-EncodedCommand
```

Attackers may use encoded commands to make command-line content less immediately readable and may use PowerShell to execute scripts, download content, launch additional processes, or interact with the operating system.

In this lab, only harmless PowerShell commands were executed.

The objective was to simulate suspicious execution patterns while generating telemetry that could be investigated in Splunk.

---

## Lab Configuration

PowerShell Operational logging was enabled on the Windows 10 workstation:

```cmd
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true
```

PowerShell Script Block Logging was enabled through the registry:

```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

The policy was applied using:

```cmd
gpupdate /force
```

The configuration was verified using:

```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

The expected result was:

```text
EnableScriptBlockLogging    REG_DWORD    0x1
```

PowerShell Operational logs were also added to the Splunk Universal Forwarder configuration:

```ini
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
```

This allowed PowerShell Event ID `4104` to be forwarded to Splunk.

---

## Attack Execution

### PowerShell Execution with Bypass Arguments

A benign PowerShell command was executed using:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Select-Object -First 5"
```

The command simply returned several running processes.

The execution included:

```text
-NoProfile
-ExecutionPolicy Bypass
```

These arguments can also appear in legitimate administration and automation, so they should be treated as investigation indicators rather than direct evidence of malicious activity.

---

### Encoded PowerShell Execution

A harmless PowerShell command was prepared:

```powershell
$cmd = 'Write-Output "PowerShell_Lab_Executed" | Out-File C:\Lab\powershell-proof.txt'
```

The command was converted to Unicode bytes:

```powershell
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
```

The bytes were Base64 encoded:

```powershell
$encoded = [Convert]::ToBase64String($bytes)
```

The encoded command was then executed using:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded
```

The benign payload wrote:

```text
PowerShell_Lab_Executed
```

to:

```text
C:\Lab\powershell-proof.txt
```

---

## Evidence Collected

Several important events were generated during PowerShell execution.

### Event ID 4104 — PowerShell Script Block Logging

PowerShell Script Block Logging recorded executed PowerShell content.

A benign test produced:

```text
Get-Process | Select-Object -First 5
```

Event ID `4104` provided visibility into the PowerShell code executed by the PowerShell engine.

This telemetry was recorded in:

```text
Microsoft-Windows-PowerShell/Operational
```

and forwarded to Splunk using the Splunk Universal Forwarder.

---

### Event ID 4104 — Encoded PowerShell Invocation

Script Block Logging also recorded the PowerShell script used to launch the encoded command:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded
```

This provided evidence that encoded PowerShell execution was initiated.

The event contained a unique ScriptBlock ID that can assist with correlating related PowerShell activity.

---

### Event ID 4688 — PowerShell Process Creation

Windows Security auditing recorded the creation of the new PowerShell process.

Observed:

```text
Account Name:
socadmin

New Process:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The command line contained:

```text
-NoProfile
-ExecutionPolicy Bypass
-EncodedCommand
```

followed by the Base64-encoded command.

Unlike the PowerShell script block event that showed the `$encoded` variable being used, Event ID `4688` exposed the actual encoded argument passed to the newly created PowerShell process.

This made the process command line an important investigation artifact.

---

## Splunk Detection

### Detect PowerShell Process Creation

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=4688
New_Process_Name="*\\powershell.exe"
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort - _time
```

Important fields include:

```text
Account_Name
Creator_Process_Name
New_Process_Name
Process_Command_Line
```

---

### Detect Potentially Suspicious PowerShell Arguments

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=4688
New_Process_Name="*\\powershell.exe"
(
    Process_Command_Line="*-EncodedCommand*" OR
    Process_Command_Line="*-enc *" OR
    Process_Command_Line="*-ExecutionPolicy Bypass*" OR
    Process_Command_Line="*-NoProfile*"
)
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort - _time
```

These arguments should not automatically be treated as malicious.

The detection should be used to identify PowerShell executions requiring additional investigation.

---

### Detect PowerShell Script Block Activity

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=4104
| sort - _time
```

Event ID `4104` allows analysts to review PowerShell script content recorded by Script Block Logging.

Important information includes:

```text
ScriptBlock ID
Script content
Computer
User context
Timestamp
```

---

### Hunt for Suspicious PowerShell Script Content

A broader hunt can look for commonly abused PowerShell functionality:

```spl
index=* host="DESKTOP-KUOONKJ" EventCode=4104
(
    "EncodedCommand" OR
    "ExecutionPolicy Bypass" OR
    "Invoke-WebRequest" OR
    "Invoke-Expression" OR
    "DownloadString"
)
| sort - _time
```

These strings are behavioral indicators and require contextual investigation because legitimate administrative scripts may contain similar functionality.

---

## Detection Logic

PowerShell activity becomes more interesting when suspicious command-line arguments are combined with script execution telemetry.

The observed activity produced:

```text
socadmin
    ↓
powershell.exe
    ↓
-NoProfile
-ExecutionPolicy Bypass
-EncodedCommand
    ↓
Base64-encoded PowerShell argument
```

Windows Security Event ID `4688` provided visibility into:

```text
Process
Command Line
User
Parent Process
```

PowerShell Event ID `4104` provided visibility into:

```text
PowerShell script blocks
Executed commands
PowerShell execution behavior
```

Together, the telemetry provides visibility into both the PowerShell process invocation and the PowerShell code being executed.

---

## Detection Workflow

1. Search Event ID `4688` for PowerShell process creation.
2. Review the account responsible for execution.
3. Examine the parent process.
4. Inspect the PowerShell command line.
5. Identify arguments such as `-EncodedCommand`, `-ExecutionPolicy Bypass`, or `-NoProfile`.
6. Pivot to PowerShell Event ID `4104` around the same timestamp.
7. Review the recorded PowerShell script block.
8. Determine what the script attempted to execute.
9. Correlate process and script telemetry by hostname, user, and timestamp.
10. Determine whether the activity is consistent with legitimate administration or requires escalation.

Observed encoded-command timeline:

| Timestamp | Event | Activity |
|---|---|---|
| 13:57:25.439 | 4104 | Script block initiated encoded PowerShell execution |
| 13:57:25.528 | 4688 | New PowerShell process created with Base64 command line |

The events occurred within approximately the same tenth of a second and represented the same PowerShell execution chain.

---

## Mitigation

Possible defensive measures include:

- Enable PowerShell Script Block Logging.
- Collect PowerShell Operational logs centrally.
- Enable Process Creation auditing with command-line logging.
- Monitor PowerShell executions using encoded commands.
- Monitor PowerShell launched from unusual parent processes.
- Investigate unnecessary use of `ExecutionPolicy Bypass`.
- Apply least privilege to administrative accounts.
- Use application control technologies such as WDAC or AppLocker where appropriate.
- Deploy endpoint protection capable of inspecting PowerShell behavior.
- Restrict unnecessary scripting capability on systems where PowerShell is not required.
- Monitor suspicious PowerShell network and child-process activity.

---

## Screenshots

### Telemetry Configuration

PowerShell Operational logging and Script Block Logging were enabled and verified.

```text
screenshots/01-telemetry-setup.png
```

### PowerShell Test Execution

Benign PowerShell execution using `-NoProfile` and `-ExecutionPolicy Bypass`.

```text
screenshots/02-powershell-execution.png
```

### Event ID 4104 — Event Viewer

PowerShell Script Block Logging showing the executed `Get-Process` command.

```text
screenshots/03-event-viewer-4104.png
```

### PowerShell Encoded Command Preparation

Creation of a harmless PowerShell payload and conversion to Base64.

```text
screenshots/04-powershell-encoded-command.png
```

### Event ID 4104 — Splunk

PowerShell Operational telemetry forwarded to Splunk showing Script Block Logging.

```text
screenshots/05-splunk-4104-detection.png
```

### Event ID 4104 — Encoded PowerShell

Script Block Logging showing the invocation of PowerShell with `-EncodedCommand`.

```text
screenshots/06-splunk-4104-encoded-command.png
```

### Event ID 4688 — Encoded PowerShell Process

Windows Security Event ID `4688` showing the PowerShell process and the Base64-encoded command line.

```text
screenshots/07-splunk-4688-encoded-command.png
```

---

## Lessons Learned

This lab demonstrated the value of combining Windows process creation telemetry with PowerShell-specific logging.

Event ID `4688` provided visibility into how PowerShell was launched, including the execution account, parent process, and command-line arguments.

This was particularly useful during encoded PowerShell execution because the process command line exposed the Base64 value passed to `-EncodedCommand`.

PowerShell Event ID `4104` provided additional visibility into script blocks executed by the PowerShell engine.

The lab also demonstrated that arguments such as `-EncodedCommand`, `-ExecutionPolicy Bypass`, and `-NoProfile` should not automatically be classified as malicious. Their presence provides behavioral context that should be correlated with the user, parent process, script content, endpoint, and surrounding activity.

PowerShell telemetry was not initially available in Splunk even though Event ID `4104` existed locally. Adding the PowerShell Operational channel to the Splunk Universal Forwarder configuration allowed the events to be centrally investigated.

Collecting both Windows Security and PowerShell Operational telemetry provides significantly better visibility into PowerShell execution than relying on process creation events alone.

# SOC Home Lab

A personal Security Operations Center lab for practicing Windows and Active Directory monitoring, attack simulation, and evidence-based investigation with Splunk.

The repository documents the environment, investigation queries, screenshots, findings, limitations, and cleanup from controlled exercises. Its focus is practical preparation for a junior SOC analyst role.

## Lab Environment

| System | Role | Lab Address |
|---|---|---|
| Windows Server 2022 — DC01 | Active Directory Domain Services and DNS for `CORP.LOCAL` | `192.168.56.10` |
| Windows 10 | Domain-joined endpoint and Splunk Enterprise host | `192.168.56.110` |
| Kali Linux | Controlled attack simulation with Impacket | Not specified here |

The VMs run in Oracle VirtualBox. Host-only networking connects the lab systems; NAT is used where internet access is required.

## Technologies and Telemetry

- **Splunk Enterprise:** indexing, searches and investigation.
- **Splunk Universal Forwarder:** collection of configured Windows event channels; the receiver listens on TCP `9997`.
- **Sysmon:** process creation and other endpoint telemetry, including Registry modifications.
- **Windows Security and System logs:** authentication, account management, group membership, scheduled tasks and service activity.
- **PowerShell Operational logs:** script block visibility.
- **Active Directory, DNS and Group Policy:** identity, domain services and logging configuration.
- **Kali Linux and Impacket:** controlled simulations.

Windows activity generates events in the configured channels. Universal Forwarders collect those events and send them to Splunk Enterprise for indexing and investigation. See the individual cases for the sources actually used.

## Investigation Portfolio

| Exercise | Main Evidence | ATT&CK Mapping Used in the Case |
|---|---|---|
| [Kerberoasting](detections/Kerberoasting/Kerberoasting.md) | Security 4769 and service ticket request output | T1558.003 |
| [AS-REP Roasting](detections/AS-REP-Roasting/AS-REP-Roasting.md) | Security 4768 and Impacket output | T1558.004 |
| [PsExec Lateral Movement](detections/PsExec-Lateral-Movement/PsExec-Lateral-Movement.md) | Authentication, SMB share access, service creation and Sysmon process creation | T1021.002, T1569.002 |
| [WMI Remote Execution](detections/WMI-Remote-Execution/WMI-Remote-Execution.md) | Security 4624 and Sysmon process creation | T1047 |
| [PowerShell Execution](detections/PowerShell-Detection/README.md) | Security 4688 and PowerShell 4104 | T1059.001 |
| [Scheduled Task Persistence](detections/Scheduled-Task-Persistence/README.md) | Security 4688 and 4698 | T1053.005 |
| [Registry Run Key Persistence](detections/RegKey-Persistence/README.md) | Sysmon 13 and 1 | T1547.001 |
| [PowerShell and Run Key Persistence](detections/PowerShell-Registry-Run-Key-Persistence/README.md) | PowerShell 4104, Sysmon 13 and 1, script output | T1059.001, T1547.001 |
| [AD Privileged Group Membership](detections/AD-Privileged-Group-Membership/README.md) | Security 4720, 4728, 4729 and 4726 | T1098.007 |

These are documented lab investigations and search examples. They should not be treated as production-ready alerts; automated correlation and deployment are only claimed where explicitly demonstrated.

## Environment Documentation

1. [Lab architecture](docs/01-Lab-Architecutre)
2. [Windows 10 deployment](docs/02-Windows-10-Virtual-Machine)
3. [Sysmon](docs/03-Sysmon)
4. [Splunk Enterprise](docs/04-Splunk-Enterprise)
5. [Splunk Universal Forwarder](docs/05-Splunk-Universal-Forwarder)
6. [Windows Server 2022](docs/06-Windows-Server-2022.md)
7. [Active Directory](docs/07-Active-Directory.md)
8. [Domain join](docs/08-Domain-Join.md)
9. [Organizational units](docs/09-Organizational-Units.md)
10. [Users and groups](docs/10-Users-and-Groups.md)
11. [Service accounts](docs/11-Service-Accounts.md)
12. [Group Policy](docs/12-Group-Policy.md)
13. [Log collection pipeline](docs/13-Windows-Event-Forwarding-Pipeline)

Deployment notes capture earlier stages of the build. Consult the later investigation documents for scenario-specific observations and configuration.

## Evidence and Limitations

Each exercise keeps its available images in a `screenshots/` subdirectory. Missing screenshots are identified rather than represented by broken links. The Registry Run Key case explicitly labels an AI-edited illustration and distinguishes it from original evidence.

The AD group membership case records a timestamp inconsistency and a temporary gap in event availability. Unverified explanations remain identified as such.

## Skills Practiced

- Windows and Active Directory administration.
- Audit policy and endpoint logging configuration.
- SIEM ingestion troubleshooting and SPL searches.
- Investigation of authentication, persistence and lateral movement.
- Correlation of accounts, processes and events using identifiers and context.
- Evidence collection, reporting and cleanup.

## Future Work

- Validate and tune reusable detection rules against benign activity.
- Add tested Sigma rules and scheduled alerts.
- Build dashboards for investigation and telemetry health.
- Improve clock consistency and forwarding diagnostics.
- Extend endpoint visibility with EDR and additional lab systems.

All simulations are intended for systems owned or explicitly authorized for testing.

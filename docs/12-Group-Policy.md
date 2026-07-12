# Group Policy Configuration

## Overview

A dedicated Group Policy Object (GPO) named **SOC Workstation Logging** was created and linked to the Workstation Organizational Unit.

The objective of this policy is to increase endpoint visibility by enabling advanced Windows auditing and PowerShell logging.

---

# Purpose

Proper Group Policy configuration ensures that endpoints generate detailed security telemetry required for threat detection and incident response.

---

# Configured Policies

## PowerShell

Enabled:

- PowerShell Script Block Logging
- PowerShell Module Logging
- PowerShell Transcription

---

## Process Creation

Enabled:

- Include command line in process creation events

This enriches Windows Security Event ID 4688 with full command-line arguments.

---

## Advanced Audit Policy

The following audit categories were enabled:

### Account Logon

- Audit Kerberos Authentication Service
- Audit Kerberos Service Ticket Operations

### Logon/Logoff

- Audit Logon

### Account Management

- Audit User Account Management

### Detailed Tracking

- Audit Process Creation

---

# Benefits

These policies significantly improve endpoint visibility by generating:

- Authentication Events
- Kerberos Events
- PowerShell Activity
- Process Creation Events
- User Management Events

This telemetry will later be forwarded to Splunk Enterprise for detection engineering and threat hunting.

---

# Skills Demonstrated

- Group Policy Administration
- Windows Auditing
- PowerShell Logging
- Endpoint Monitoring
- Enterprise Logging Configuration

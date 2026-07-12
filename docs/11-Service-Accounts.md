# Service Accounts

## Overview

Dedicated service accounts were created to simulate enterprise applications running under domain identities.

Unlike standard user accounts, service accounts are intended for applications and services rather than interactive logins.

---

# Service Accounts

| Service | Username |
|----------|----------|
| SQL Service | svc_sql |
| Backup Service | svc_backup |
| Web Service | svc_web |

---

# Configuration

Each account was configured with:

- Password Never Expires
- Standard domain user permissions

---

# Service Principal Names (SPNs)

To simulate enterprise Kerberos authentication, Service Principal Names (SPNs) were assigned.

Examples:

- MSSQLSvc/sql.corp.local:1433
- HTTP/web.corp.local

These SPNs allow Kerberos clients to request service tickets and provide realistic telemetry for future Kerberoasting demonstrations.

---

# Purpose

Service accounts will later be used for:

- Kerberos Authentication
- Kerberoasting
- Detection Engineering
- Threat Hunting

---

# Skills Demonstrated

- Active Directory Service Accounts
- Service Principal Names (SPNs)
- Kerberos Configuration

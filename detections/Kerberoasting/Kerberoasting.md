# Kerberoasting Detection

## Detection Summary

| Field | Value |
|-------|-------|
| Attack | Kerberoasting |
| MITRE ATT&CK | T1558.003 |
| Tactic | Credential Access |
| Platform | Active Directory |
| Detection Platform | Splunk Enterprise |
| Primary Event ID | 4769 |
| Status | ✅ Successfully Simulated |

---

# Objective

Demonstrate and detect a Kerberoasting attack in an Active Directory environment by requesting Kerberos service tickets (TGS) for Service Principal Names (SPNs) and identifying the resulting Windows Security events in Splunk.

---

# MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Kerberoasting | T1558.003 |

---

# Lab Environment

| Machine | Role |
|---------|------|
| Kali Linux | Attacker |
| DC01 | Domain Controller |
| WIN10 | Splunk Enterprise & Universal Forwarder |

**Domain**

```
corp.local
```

---

# Attack Overview

Kerberoasting is a credential access technique that targets Active Directory service accounts associated with a Service Principal Name (SPN).

An authenticated domain user can request a Kerberos Ticket Granting Service (TGS) ticket for a service account. The ticket is encrypted using the service account's password hash and can be extracted and cracked offline to recover the plaintext password.

Unlike many attacks, Kerberoasting requires only a standard domain user account and does not require administrative privileges.

---

# Lab Configuration

A service account with an SPN was configured in Active Directory.

Example SPN:

```
MSSQLSvc/sql.corp.local:1433
```

---

# Attack Execution

## Tool

Impacket

## Command

```bash
impacket-GetUserSPNs 'CORP.LOCAL/rsmith:<password>!' \
-dc-ip 192.168.56.10 \
-request
```

## Result

The attack successfully requested a Kerberos service ticket and returned a crackable Kerberos TGS hash.

Example:

```
$krb5tgs$23$...
```

---

# Evidence Collected

## Windows Security Log

**Event ID**

```
4769
```

**Relevant Fields**

- Account Name
- Service Name
- Client Address
- Ticket Encryption Type

---

# Splunk Detection

## Basic Search

```spl
index=* host=DC01 EventCode=4769
```

## Detection Query

```spl
index=* host=DC01 EventCode=4769 Ticket_Encryption_Type=0x17
| stats count values(Service_Name) AS Service values(Client_Address) AS Source_IP BY Account_Name
| sort - count
```

---

# Detection Logic

Kerberoasting generates Kerberos Service Ticket requests (Event ID 4769).

A high volume of TGS requests, especially using RC4 encryption (0x17), originating from a single client may indicate Kerberoasting activity.

While RC4 is not malicious by itself, unexpected or excessive requests for multiple service accounts should be investigated.

---

# Detection Workflow

```
Kali Linux
        │
        ▼
Kerberos TGS Request
        │
        ▼
Domain Controller (DC01)
        │
        ▼
Windows Security Event 4769
        │
        ▼
Splunk Universal Forwarder
        │
        ▼
Splunk Enterprise
        │
        ▼
Detection
```

---

# MITRE Mapping

| Tactic | Technique |
|---------|-----------|
| Credential Access | T1558.003 – Kerberoasting |

---

# Mitigation

- Use strong, long passwords for service accounts.
- Prefer Group Managed Service Accounts (gMSAs).
- Disable RC4 where possible and enforce AES encryption.
- Audit Service Principal Names (SPNs) regularly.
- Monitor abnormal volumes of Event ID 4769.
- Rotate service account passwords periodically.

---

# Screenshots

- `impacket-getuserspns.png` – Successful Kerberoasting attack and extracted TGS hash.
- `detection-search-results.png` – Splunk detection query and matching Event ID 4769 results.
- `event-viewer-4769.png` – Windows Security Log showing Event ID 4769 on the Domain Controller.

---

# Lessons Learned

This lab demonstrated the complete Kerberoasting attack lifecycle in a controlled Active Directory environment.

Key takeaways:

- Successfully simulated Kerberoasting using Impacket.
- Generated Windows Security Event ID 4769.
- Collected telemetry using the Splunk Universal Forwarder.
- Detected the activity in Splunk Enterprise using custom SPL queries.
- Mapped the attack to MITRE ATT&CK T1558.003 and documented potential mitigations.

This exercise reinforced the importance of monitoring Kerberos service ticket activity and properly securing service accounts within Active Directory environments.

            Detection Summary                          
------------------ | ------------------------ 
Attack             | Kerberoasting            
MITRE ATT&CK       | T1558.003                
Windows Event IDs  | 4769                     
Data Source        | Windows Security Log     
Detection Platform | Splunk Enterprise          
Difficulty         | ⭐⭐☆☆☆                 
Status             | ✅ Successfully Simulated 

# Kerberoasting Detection

## Objective

Detect Kerberoasting activity by monitoring Kerberos service ticket requests (Event ID 4769) generated from user accounts requesting service tickets for Service Principal Names (SPNs).

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
| WIN10 | Splunk Enterprise |

Domain:

corp.local

---

# Attack Overview

Kerberoasting abuses Kerberos authentication by requesting service tickets associated with Service Principal Names (SPNs). Since the tickets are encrypted using the service account's NTLM hash, they can be exported and cracked offline.

---

# Attack Execution

Tool:

Impacket

Command:

bash
`impacket-GetUserSPNs 'CORP.LOCAL/rsmith:P@ssword123!' \
-dc-ip 192.168.56.10 \
-request`

Result:

Successfully obtained a Kerberos TGS hash.

---

# Evidence Collected

Windows Security Log

Event ID:

4769

Relevant fields:

- Account Name
- Service Name
- Client Address
- Ticket Encryption Type

---

# Splunk Detection

Basic query

```spl
index=* host=DC01 EventCode=4769
```

RC4 Detection

```spl
index=* host=DC01 EventCode=4769 Ticket_Encryption_Type=0x17
| stats count values(Service_Name) by Account_Name Client_Address
```

---

# Detection Logic

Repeated service ticket requests using RC4 encryption from a workstation may indicate Kerberoasting activity.

---

# MITRE Mapping

Credential Access

T1558.003

---

# Mitigation

- Use AES-only Kerberos encryption
- Use gMSAs where possible
- Rotate service account passwords
- Monitor unusual 4769 activity
- Remove unnecessary SPNs

---

# Screenshots

- Impacket output
- Splunk search
- Event Viewer
- Detection dashboard

---

# Lessons Learned

This lab demonstrates the full attack lifecycle:

Kali

↓

Active Directory

↓

Windows Event Logs

↓

Universal Forwarder

↓

Splunk Enterprise

↓

Detection

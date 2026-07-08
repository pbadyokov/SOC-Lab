# Active Directory Domain Services (AD DS)

## Overview

Active Directory Domain Services (AD DS) provides centralized identity and access management for Windows environments.

Within this lab, AD DS is used to authenticate users, manage computers, organize resources, and simulate an enterprise network.

---

# Purpose

The goal of deploying Active Directory is to create a realistic Windows domain environment suitable for attack simulation, threat detection, and incident response.

---

# Deployment

Installed the Active Directory Domain Services role using Server Manager.

The server was promoted to a Domain Controller by creating a new forest.

Domain:

corp.local

Hostname:

DC01

---

# DNS

During promotion, the DNS Server role was installed automatically.

DNS provides name resolution for all domain-joined systems and is required for Active Directory to function correctly.

---

# Verification

Verified successful deployment by confirming:

- Domain Controller promotion
- corp.local domain creation
- Active Directory Users and Computers
- DNS Forward Lookup Zone
- _msdcs zone creation

---

# Enterprise Benefits

Active Directory enables:

- Centralized authentication
- Group Policy
- Kerberos
- Organizational Units
- User and Computer Management
- Service Accounts

---

# Skills Demonstrated

- Active Directory
- Domain Controller Deployment
- Forest Creation
- DNS Integration
- Enterprise Authentication

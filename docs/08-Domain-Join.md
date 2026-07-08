# Domain Join

## Overview

The Windows 10 workstation was joined to the corp.local Active Directory domain.

Joining the workstation enables centralized authentication, policy management, and enterprise administration.

---

# Prerequisites

Before joining the domain:

- Active Directory deployed
- DNS configured
- Static IP configured on DC01
- Windows 10 DNS pointed to 192.168.56.10

---

# Configuration

Preferred DNS:

192.168.56.10

Domain:

corp.local

---

# Verification

Successfully joined the workstation to the domain.

Authenticated using:

CORP\Administrator

After reboot, Windows recognized the workstation as a domain member.

---

# Benefits

Joining the domain allows:

- Kerberos authentication
- Group Policy
- Centralized user management
- Enterprise logon
- Active Directory integration

---

# Skills Demonstrated

- Windows Domain Administration
- Active Directory Integration
- DNS Configuration
- Enterprise Authentication

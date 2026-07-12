# Organizational Units (OUs)

## Overview

Organizational Units (OUs) were created to organize Active Directory objects into a logical hierarchy that resembles a small enterprise environment.

Unlike the default Active Directory containers, OUs provide administrative organization and allow Group Policy Objects (GPOs) to be applied to specific groups of users and computers.

---

# Purpose

The objective of implementing Organizational Units is to:

- Organize users and computers
- Simplify administration
- Apply Group Policies to specific departments
- Simulate an enterprise Active Directory structure

---

# Organizational Structure

```
CORP.LOCAL
│
├── Admins
├── Company Users
│   ├── IT
│   ├── HR
│   ├── Finance
│   ├── Marketing
│   └── Management
│
├── Groups
├── Servers
├── Service Accounts
└── Workstation
```

---

# Benefits

The OU structure allows:

- Department separation
- Simplified administration
- Targeted Group Policy deployment
- Better scalability

---

# Skills Demonstrated

- Active Directory Administration
- Organizational Unit Design
- Enterprise Environment Planning

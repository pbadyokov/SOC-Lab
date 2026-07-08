# Windows Server 2022 Deployment

## Overview

Windows Server 2022 serves as the foundation of the Active Directory environment within the SOC Home Lab.

The server hosts Active Directory Domain Services (AD DS) and DNS, providing centralized authentication, authorization, and name resolution for all domain-joined systems.

---

# Purpose

The objective of deploying Windows Server 2022 is to simulate an enterprise infrastructure where endpoints authenticate against a centralized Domain Controller.

---

# Environment

| Component | Value |
|-----------|-------|
| Operating System | Windows Server 2022 Standard Evaluation (Desktop Experience) |
| Hostname | DC01 |
| Role | Domain Controller |
| Virtualization | Oracle VirtualBox |

---

# VM Configuration

| Resource | Value |
|----------|-------|
| Memory | 4 GB |
| CPU | 2 vCPUs |
| Storage | 100 GB Dynamic |
| Network | Host-Only + NAT |

---

# Network Configuration

The server was configured with a static IP address.

| Setting | Value |
|----------|-------|
| IP Address | 192.168.56.10 |
| Subnet Mask | 255.255.255.0 |

A static IP ensures that clients can consistently locate DNS and Active Directory services.

---

# Installation

- Installed Windows Server 2022 Desktop Experience
- Renamed the server to DC01
- Configured a static IPv4 address
- Verified network connectivity

---

# Skills Demonstrated

- Windows Server Administration
- Static IP Configuration
- Virtual Networking
- Server Deployment

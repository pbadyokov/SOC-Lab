# User and Security Group Management

## Overview

A realistic enterprise user structure was created to simulate employees across multiple departments.

Security Groups were also created to simplify permission management and future Group Policy assignments.

---

# Purpose

The goal was to replace the default Active Directory accounts with realistic organizational users.

This provides a more accurate environment for authentication events, Kerberos traffic, and attack simulations.

---

# Departments

## IT

- John Miller (jmiller)
- Michael Brown (mbrown)

## HR

- Alice Johnson (ajohnson)
- Sarah Wilson (swilson)

## Finance

- Robert Smith (rsmith)
- Emma Davis (edavis)

## Marketing

- David Clark (dclark)
- Olivia Taylor (otaylor)

## Management

- James Anderson (janderson)

---

# Security Groups

The following Global Security Groups were created:

- IT_Admins
- IT_Users
- HR
- Finance
- Marketing
- Management

Users were assigned to the appropriate security groups according to their department and role.

---

# Benefits

Using Security Groups instead of assigning permissions directly to users simplifies administration and follows enterprise best practices.

---

# Skills Demonstrated

- Active Directory User Administration
- Security Group Management
- Role-Based Access Control (RBAC)

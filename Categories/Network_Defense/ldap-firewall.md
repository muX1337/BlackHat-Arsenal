# LDAP Firewall

## Description
The Lightweight Directory Access Protocol (LDAP) is used in Windows domain environments to interact with the Active Directory schema, allowing users to query information and modify objects (such as users, computers, and groups). For a Windows environment to properly function, LDAP must be left open on the Domain Controllers and be accessible to all users of the domain. As only limited logs are available for LDAP, and it is impossible to natively harden the LDAP configuration, the environment is at a constant risk.

LDAP Firewall is an open-source tool for Windows servers that lets you audit and restrict incoming LDAP requests. Its primary use cases are to protect Domain Controllers, block LDAP-based attacks (such as BloodHound and sAMAccountName spoofing), and tightly control access to the Active Directory schema.

We will present the LDAP Firewall, demonstrating how it defends against previously un-detectable attacks by hardening and monitoring the DC servers. We will also discuss the reverse-engineering process of the Windows LDAP library, how the protocol works, and the technical details of the LDAP Firewall.

## Code
https://github.com/zeronetworks/ldapfw

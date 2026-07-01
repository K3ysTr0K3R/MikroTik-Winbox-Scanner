# Winbox Protocol Scanner (MikroTik RouterOS)

A high-performance concurrent scanner designed to detect exposed MikroTik Winbox services on the internet.  
This tool identifies active Winbox endpoints on TCP port 8291 and classifies RouterOS response behavior to determine service availability.
Note that there are so many Winbox protocols exposed to the internet, this tool should be enough to scare so you can prevent your router device from cyber attacks.
Attackers can find these protocols to exploit CVE-2018-14847 that gives them the ability to steal credentials from these devices.

It is intended for authorized security research, exposure analysis, and defensive network auditing.

---

## Overview of Winbox Protocol

Winbox is a proprietary management protocol used by MikroTik RouterOS for remote administration of network devices. It operates over TCP (default port `8291`) and provides a graphical interface for configuration and management of routers and network infrastructure.

Unlike standard web-based management interfaces, Winbox uses a custom binary protocol optimized for performance and low overhead. It is widely deployed in ISP environments, enterprise networks, and edge routing infrastructure.

### Key Properties

- Protocol Type: Proprietary binary TCP protocol  
- Default Port: 8291/tcp  
- Primary Function: RouterOS remote administration  
- Authentication: Username and password-based session negotiation  
- Deployment: MikroTik routers, ISP infrastructure, enterprise edge devices  

---

## Internet Exposure Risks

When Winbox is exposed to the public internet, it significantly increases the attack surface of a network device.

Common risks include:

- Brute-force authentication attempts
- Credential reuse attacks
- Automated internet-wide scanning
- Misconfiguration exploitation
- Exposure of outdated RouterOS services

In many real-world cases, Winbox exposure occurs due to misconfigured firewall rules or administrative interfaces being left open on WAN-facing interfaces.

---

## CVE-2018-14847 Security Context

CVE-2018-14847 is a critical vulnerability affecting MikroTik RouterOS versions up to 6.42. It involves a directory traversal flaw in the Winbox interface that allows attackers to access sensitive files on affected devices. There are so many Winbox protocols afected by this vulnerability, this vuln can leade to credential leakage.

### Impact Summary

- Unauthenticated attackers may read arbitrary files from affected devices 
- Authenticated attackers may modify or write arbitrary files  
- Sensitive configuration data, including credentials, may be exposed  

This vulnerability has been widely discussed in security research due to its real-world exploitation and impact on internet-exposed MikroTik devices.

### Technical Background

The vulnerability exists due to insufficient validation of file path inputs within Winbox file handling mechanisms. By manipulating path traversal sequences, attackers can escape restricted directories and access internal system files.

---

## Research and Defensive Relevance

Understanding Winbox behavior and exposure patterns is important for:

- Identifying misconfigured internet-facing routers  
- Reducing attack surface in ISP and enterprise environments  
- Supporting threat intelligence and exposure monitoring  
- Validating patch levels across network infrastructure  

This scanner is designed to assist in identifying exposed services and improving defensive visibility.

---

## Tool Description

This project is a concurrent Winbox detection scanner that:

- Detects active Winbox services on TCP port 8291  
- Supports single IP, CIDR ranges, and file-based input  
- Performs fast concurrent scanning using worker pools  
- Identifies Winbox handshake responses (modern and legacy RouterOS behavior)  
- Provides real-time progress tracking and result logging  

---

## CVE Research and Proof of Concept

This scanner is part of broader research into MikroTik RouterOS security issues, including:

- CVE analysis and exploitation behavior  
- Winbox protocol exposure patterns  
- RouterOS authentication and file access weaknesses  

Remember that this scanner is seperate from the CVE.
This specific tool is to detect Winbox protocols, you can find the PoC exploit for it here:

https://github.com/K3ysTr0K3R/CVE-2018-14847-EXPLOIT

---

## Defensive Recommendations

To reduce exposure and mitigate risk:

- Restrict Winbox access to trusted IP ranges only  
- Disable Winbox on WAN interfaces  
- Use VPN or SSH tunneling for administrative access  
- Ensure RouterOS is fully updated  
- Monitor logs for unauthorized access attempts  
- Enforce strict firewall policies on management ports  

---

## Disclaimer

This tool is intended for authorized security research and defensive purposes only.  
Unauthorized scanning or testing of systems without permission may violate laws and regulations.

---

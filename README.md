# 🛡️ Email Threat Intelligence Project

**Author:** Samuel Akinleye  
**Date:** October 2025  

---

## 🧭 Overview

This project presents a comprehensive **Email Threat Intelligence** investigation focused on analysing and mitigating a phishing-based cyber incident.  
It demonstrates the process of identifying, examining, and responding to a suspicious email impersonating Microsoft using both manual inspection and automated threat intelligence tools.

The project serves as a professional case study in **email forensics**, **incident response**, and **cyber threat intelligence** operations within a Security Operations Centre (SOC) context.

---

## 🎯 Objective

The objectives of this analysis are to:

- Conduct a full forensic investigation of a phishing email.  
- Demonstrate advanced techniques for analysing email headers and body content.  
- Cross-reference indicators of compromise (IOCs) using multiple threat intelligence sources.  
- Provide actionable recommendations to enhance email security and user awareness.

---

## 🧰 Tools and Technologies

| Category | Tools Used |
|-----------|-------------|
| **Email Inspection & Parsing** | Mozilla Thunderbird, Notepad++, Google Admin Toolbox, Sendmarc Analyzer |
| **Command-Line & Scripting** | grep, curl, whois, dig, exiftool |
| **Threat Intelligence** | VirusTotal, AlienVault OTX, AbuseIPDB, URLScan.io, Whois.domaintools |

---

## 🧪 Project Scope

This project covers the following technical aspects:

1. **Email Header Analysis** — Verifying sender identity, IP traceability, and SPF/DKIM/DMARC authentication.  
2. **Email Body Analysis** — Extracting URLs, identifying hidden trackers, and analysing HTML content.  
3. **Threat Intelligence Correlation** — Validating suspicious domains and IPs through intelligence databases.  
4. **Recommendations** — Strengthening organizational security posture and awareness.

---

## 🧠 Executive Summary

On **03 October 2025**, the Security Operations Centre (SOC) received a suspicious email reported by an employee.  
The email impersonated Microsoft, urging the recipient to verify their account through a malicious link.

The investigation confirmed that:

- The sender domain `access-accsecurity.com` is unaffiliated with Microsoft.  
- SPF, DKIM, and DMARC authentication failed across all checks.  
- The originating IP `89.144.44.41` was traced to a non-Microsoft network.  
- Malicious domains `sign.in` and `thebandalisty.com` were identified as phishing and tracking sources.  

All indicators of compromise (IOCs) were blocked across both network and endpoint layers.  
No user compromise was detected following the incident.

---

## 🧩 Key Findings

| Indicator Type | Value | Verdict |
|----------------|--------|----------|
| **Domain** | access-accsecurity.com | Spoofed |
| **IP Address** | 89.144.44.41 | Suspicious |
| **URL** | https://sign.in | Malicious |
| **Tracking Domain** | thebandalisty.com | Malicious |

---

## 🖼️ Screenshots

Include relevant screenshots that demonstrate your investigative workflow and tool outputs.

```markdown
![Header Analysis](assets/screenshots/screenshot-01.png)
![Google Toolbox Results](assets/screenshots/screenshot-02.png)
![Email Body Inspection](assets/screenshots/screenshot-03.png)

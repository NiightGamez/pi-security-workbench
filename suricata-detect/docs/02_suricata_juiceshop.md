# Lab 02: Network Intrusion Detection (NIDS) with Suricata & OWASP Juice Shop

## 1. Objective
Deploy Suricata to sniff an isolated container bridge network (`docker0`), inspect Layer-7 HTTP streams, and engineer custom detection rules to catch common web attacks against OWASP Juice Shop.

## 2. ATT&CK Mapping
- **T1190**: Exploit Public-Facing Application
- **T1059.004**: Command and Scripting Interpreter (Command/SQL Injection)
- **T1083**: File and Directory Discovery (Path Traversal)

## 3. Implemented Signatures (`local.rules`)
- **`sid:1000003` (Rev 1)**: SQL Injection Boolean Tautology (`' OR 1=1`) matching on normalized `http.uri` using PCRE regex evaluation.
- **`sid:1000004` (Rev 2)**: Directory Traversal targeting `/ftp` file structures using `http.uri.raw` to detect evasive percent-encoded traversal sequences (`..%2f`).

## 4. Detection Telemetry (`fast.log`)
Both alerts triggered with Priority 1 severity against ingress traffic from the Docker gateway (`172.17.0.1`) targeting the Juice Shop container (`172.17.0.2:3000`):
- `09/22/2026-06:42:44` | `[1:1000003:1]` | SQLi Tautology Detected | `172.17.0.1:41782 -> 172.17.0.2:3000`
- `09/22/2026-06:44:05` | `[1:1000004:2]` | Directory Traversal Attempt | `172.17.0.1:46878 -> 172.17.0.2:3000`

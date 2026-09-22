# Lab Notes: Network Detection Engineering — Custom Suricata Signatures vs. DVWA

## 1. Executive Summary & Concept
* **Objective:** Transition from host-based telemetry (`auditd`) to Network Intrusion Detection System (**NIDS**) operations. You will inspect live application-layer traffic, identify web exploitation patterns, and engineer custom detection rules from scratch.
* **Core Idea:** Run Damn Vulnerable Web App (**DVWA**) on an isolated Docker bridge network, send common web exploit payloads against it, and configure **Suricata** to sniff that traffic in real time.
* **Why it Works:** Web applications process untrusted user input. By analyzing the Layer 7 (HTTP) protocol stream at the packet boundary, a NIDS flags malicious intent (directory traversal, command injection, SQLi) before or as it reaches the backend runtime.

---

## 2. CompTIA CySA+ Exam Mapping
* **Primary Domain:** Security Operations and Monitoring / Vulnerability Management.
* **Detection Mechanism:** **NIDS** (Network Intrusion Detection System) / Signature-based analysis.
* **ATT&CK Techniques Simulated:**
  * **T1059.004 (Command and Scripting Interpreter: Unix Shell):** Attacker leverages vulnerable web inputs to spawn system commands (`cat`, `whoami`, `id`).
  * **T1083 (File and Directory Discovery):** Traversing directory trees (`../../../../etc/passwd`) via unsanitized file inclusion parameters.
* **Core Contrast for CySA+:**
  * **HIDS (`auditd`):** Analyzes what happened *inside the kernel* (e.g., system call executed, binary run on disk).
  * **NIDS (`suricata`):** Analyzes what traveled *across the wire* (e.g., packet payloads, HTTP methods, headers, URIs).

---

## 3. Architecture & Mechanics: How Suricata Inspects Traffic

```text
[ Attacker / curl ] 
        |
        v
  [ docker0 Bridge ]  <--- (Promiscuous mode packet capture via AF_PACKET)
        |                       |
        |                       v
        |               [ Suricata Engine ]
        |                       |
        |             Parses Layer 7 (HTTP buffers)
        |             Evaluates active rules / PCRE
        |                       |
        |                       v
        |            Logs alert to: /var/log/suricata/fast.log
        v
[ DVWA Target Container (Port 80) ]

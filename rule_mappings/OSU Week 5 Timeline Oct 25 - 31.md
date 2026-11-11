# OSU Week 5 Timeline Objectives: Enrichment Alert

## Rules Documentation and TTP Mapping

### Objective 3.4 MITRE ATT&CK Mapping
**Purpose:** Identify the tactics and techniques from a rule’s detection logic.

---

#### 🛡️ Rule 1: Potential Invoke – Mimikatz PowerShell Script

##### MITRE ATT&CK Mappings

* **Tactic:** Credential Access (TA0006)
  * **Techniques:** 
    * OS Credential Dumping (T1003)
    * Credential from Password Stores (T1555)
    * Steal or Forge Authentication Certificates (T1649)
    * Steal or Forge Kerberos Tickets (T1558)
  * **Evidence:** This rule searches PowerShell script content for commands that are associated with credential dumping, password store access, certificate export, and Kerberos ticket activity. The specific technique mapping depends directly on what pattern triggers the alert.
  * **References:**
    * [MITRE ATT&CK - Mimikatz](https://mitre.org)
    * [Empire Project Source - GitHub](https://githubusercontent.com)
    * [Elastic Security Labs - Credential Access](https://elastic.co)

* **Tactic:** Lateral Movement (TA0008)
  * **Technique:** Use Alternate Authentication Material (T1550)
  * **Evidence:** This rule includes patterns associated with using alternate authentication material, such as pass-the-hash behavior. This supports a potential T1550 mapping but does not independently prove that authentication to a remote system was successful.

##### Technical Framework

* **Detection Limitations:** 
  * Requires explicit PowerShell script block logging (`Event ID 4104`).
  * Matches static content patterns; heavily obfuscated or modified commands may evade detection entirely.
  * An alert indicates intent/behavior but does not confirm successful credential theft, certificate export, or subsequent lateral movement.
  * Authorized red-team penetration testing or administrative audits will trigger this alert.

* **Mapping Explanation:** 
  * These mappings describe behaviors covered by the rule logic. 
  * They do not imply that every single technique occurs simultaneously when an alert fires. 
  * Analysts must check the deployed rule version and investigate the matching script text details.

---

#### 🛡️ Rule 2: Potential Command Shell via NetCat

##### MITRE ATT&CK Mappings

* **Tactic:** Execution (TA0002)
  * **Technique:** Command and Scripting Interpreter (T1059)
  * **Evidence:** This rule detects `cmd.exe` or `powershell.exe` spawning under a parent process with arguments matching NetCat shell execution syntax.
  * **References:** None provided on Kibana.

* **Tactic:** Command and Control (TA0011)
  * **Technique:** Non-Application Layer Protocol (T1095)
  * **Evidence:** Detected command-line arguments point to an active connecting or listening shell. This functions as a potential C2 network channel. Network telemetry is required to verify actual socket communication.

##### Technical Framework

* **Detection Limitations:** 
  * Relies entirely on Windows process creation events and specific argument substring matching.
  * Alternative or custom reverse shell execution methods may bypass these signatures.
  * Does not independently confirm a successful network connection, active remote control session, or malicious threat actor intent.
  * Authorized emergency systems engineering or network testing can mirror this behavior.

* **Mapping Explanation:** 
  * **Execution** defines the initial action of the command interpreter spawning. 
  * **Command and Control** outlines the potential raw network transport channel used to pivot or push instructions. 
  * These mappings categorize the indicators found rather than verifying an accomplished exploit state.

---

#### 🛡️ Rule 3: Potential Privilege Escalation via Python cap_setuid

* **Tactic Name & ID:** *[Pending Context Capture]*
* **Technique & ID:** *[Pending Context Capture]*
* **Evidence Supporting Mapping:** *[Pending Context Capture]*
* **Detection Limitations:** *[Complete during rule onboarding phase]*
* **Mapping Explanation:** *[Complete during rule onboarding phase]*

> 💡 **Enrichment Note:** If the working group approves more rules, insert their structured profiles directly here.

---
---

### Objective 3.5 Adversary Procedures and Client Attack Vectors
**Purpose:** High-level operational documentation mapping how threat actors execute targeted behaviors and their downstream effects on client environments (aggregated to preserve anonymity).

#### 🎯 Vector Profiles

* **Potential Attack Vectors:**
  * **Phishing:** Social engineering delivery channels via email, workspace chat, or voice.
  * **Credential Theft:** Active Man-in-the-Middle (MitM) positioning or local caching harvesting.
  * **Vulnerable Endpoints:** Missing software patches on internet-accessible or internal infrastructure.
  * **Lack of MFA:** Missing or weak multi-factor requirements on high-privilege domain/cloud administrator accounts.

* **Tactics, Techniques, Procedures (TTPs):**
  * Exploit Public-Facing Application (`T1190`)
  * Search Victim-Owned Websites (`T1594`)
  * Gather Victim Host Information (`T1592`)
  * Initial Access (`TA0001`)
  * Phishing (`T1566`)
  * Supply Chain Compromise (`T1195`)
  * Reconnaissance (`TA0043`)
  * Search Open Websites/Domains (`T1593`)
  * Command and Scripting Interpreter (`T1059`)

* **Threat Actors:**
  * Organized Cybercriminal Groups (Financial/Ransomware focus)
  * Nation-State Advanced Persistent Threats (APTs) (Espionage/Exfiltration focus)
  * Script Kiddies (Opportunistic/Automated scanning focus)

#### 🔄 Adversary Procedure Walkthrough
*Example Lifecycle: Potential Invoke-Mimikatz PowerShell Script*

1. **Starting Conditions:** The adversary establishes initial code execution privileges on an internal Windows host. Note that deep credential dumping mechanisms may require local administrator or SYSTEM token privileges.
2. **Attacker Behavior:** The attacker triggers an automated or interactive PowerShell session loading explicit Mimikatz commands into runtime memory to scrape cleartext secrets or hashes.
3. **Detected Activity:** The monitoring framework captures explicit string footprints inside the Windows PowerShell script block logging sub-system.
4. **Possible Escalating Activity:** If secrets are gathered successfully, the threat actor pivots horizontally across client environments using valid matching credentials.

#### ⚠️ Downstream Client Impact
* Financial Resource Loss
* Compromised Proprietary Client Projects
* Sensitive & Protected Data Exposure
* Severely Degraded Core System Availability
* Damaged Client Trust Ecosystem
* Host Machine Control Hijacking

---
---

### Objective 3.6 Investigation Baseline Questions and False Positive Checks
**Purpose:** Establish standardized operational playbooks for incident response personnel handling these triggers.

#### Playbook 1: Potential Invoke-Mimikatz PowerShell Script

##### 🔍 Critical Triage Questions
* **Scope Tracking:** Which target endpoint asset, system account identity, and precise timestamp are attached to this alert?
* **Payload Analysis:** What is the full functional outcome of the PowerShell script code? (*Examine full script blocks and reconstructed fragments*).
* **Execution Lineage:** How was the original PowerShell process launched? (*Inspect the execution tree, parent identity, and complete argument arrays*).
* **Authorization Check:** Is there a documented, active security verification assessment, penetration test, or internal training drill occurring right now?
* **Post-Exploit Verification:** Are secondary system logs showing signs of active local credential database manipulation or unauthorized document file staging?
* **Horizontal Shift Tracking:** Do network logs reveal strange or out-of-character secondary authentications originating from the compromised node?

##### 🟢 Benign Validation Checklist
* **Authorized Security Testing:** Review active authorization logs. Ensure target scopes, times, and engineers align with the exact machine alert signatures.
* **Malware Analysis / Training:** Check if the host sits inside a dedicated, isolated malware engineering laboratory or sandbox environment.
* **Inactive Code Context:** Inspect the full script block payload to verify if the string pattern was non-functional static text inside an informational asset or note instead of actual code.

##### 📋 Findings and Escalation Policy
Log all concrete supporting telemetry confirming either malicious intent or an authorized source. Escalate unresolved high-severity indicators immediately via established ORTSOC standard pathways. 
* *Operational Rule:* Access blocks or absent logs must be categorized as investigation constraints. They should never be arbitrarily used as evidence of a benign false-positive.

* **Investigation Findings:** `[Completed by triage analyst]`
* **Open Unresolved Questions:** `[Completed by triage analyst]`
* **Operational Disposition / Next Steps:** `[Record definitive sign-off conclusion and tracking ticket references]`

---

#### Playbook 2: Potential Command Shell via NetCat

##### 🔍 Critical Triage Questions
* **Scope Tracking:** What exact asset node, operational profile, and precise time window are bound to this alert footprint?
* **Spawning Lineage:** What software parent process called `cmd.exe` or `powershell.exe`? (*Analyze executable path strings and process hash identities*).
* **Shell Directionality:** Do process command arguments reveal an outgoing connection shell setup or an active, open local socket listener profile?
* **Network Integrity Check:** Do firewall or connection tracking systems back up the presence of a network connection or open listener socket? (*Map IP structures and port pairings*).

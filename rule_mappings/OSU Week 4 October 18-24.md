# OSU Week 4 Objectives

## Objective 3.1: Selected Target Detection Rules (Proposed)
**Purpose:** Technical selection matrix analyzing core alerts proposed for pipeline integration and optimization.

---

### 📋 Candidate Rule Profiles

#### 1. Potential Command Shell via NetCat
* **Rule Core Type:** Event Correlation
* **Severity Matrix Score:** High / 73
* **Functional Description:** Monitors for remote command execution vectors. Specifically flags `cmd.exe` or `powershell.exe` instances spinning up from parent tasks using argument syntax typical of reverse network shell utilities.
* **Selection Rationale:** This baseline indicator isolates illegal external host takeover attempts. Incorporating command arguments, local identity boundaries, and traffic telemetry within our enrichment workflow allows analyst teams to quickly filter true-positive threats out from authorized network baseline tests.

#### 2. Telnet Authentication Bypass via User Environment
* **Rule Core Type:** Event Correlation
* **Severity Matrix Score:** Critical / 99
* **Functional Description:** Triggers on exploitation attempts targeting Linux host environments utilizing the historical authentication bypass vulnerability `CVE-2026-24061` within GNU inetutils `telnetd`. Captures crafted `-f <username>` injection values passed inside the `USER` environment layer.
* **Selection Rationale:** Spotlights immediate privilege escalation tracks that lead to unauthorized root infrastructure control. Enrichment strategies provide contextual daemon profiles, parameter arguments, tracking parameters, and post-exploit auditing to speed up impact verification.

#### 3. Potential Invoke – Mimikatz PowerShell Script
* **Rule Core Type:** Query Signature
* **Severity Matrix Score:** Critical / 99
* **Functional Description:** Audits Windows environment script content to pinpoint explicit instances of memory-dump commands designed to parse active password vaults, grab raw local hashes, or extract digital certificate profiles.
* **Selection Rationale:** Flags hazardous internal credential theft behaviors that fuel network pivoting. Workflow enrichment exposes structured code execution context, active parent process profiles, and associated authentication logs to determine if actions are real exploits or authorized IT audits.

#### 4. Potential Privilege Escalation via Python cap_setuid
* **Rule Core Type:** Event Correlation
* **Severity Matrix Score:** High / 73
* **Functional Description:** Scans Unix-family execution records for sequence anomalies where Python invokes system tasks leveraging explicit setuid or setgid file capabilities, instantly followed by account context switches to root.
* **Selection Rationale:** *[Awaiting final working group sign-off summary]*

#### 5. Potential Credential Access via LSASS Memory Dump
* **Rule Core Type:** Event Correlation
* **Severity Matrix Score:** High / 73
* **Functional Description:** Monitors memory space hooks into the Local Security Authority Subsystem Service (`lsass.exe`) where call trace stacks route directly through `DBGHelp.dll` or `DBGCore.dll` library files.
* **Selection Rationale:** *[Awaiting final working group sign-off summary]*

---

### ⚙️ Consensus & Project Scoping

* **Agreed Target Footprint:** 3 Rules Core Selection
* **Active Target Roster:**
  1. Rule 1: Potential Invoke – Mimikatz PowerShell Script
  2. Rule 2: Potential Command Shell via NetCat
  3. Rule 3: *[Pending Final Group Consensus]*
* **Milestone Dates:** Selection Confirmed 10/?/2026
* **Project Dependencies:** None

---

### 📝 Detection Rule Documentation Requirements

* **Operational Purpose:** Establish an accessible knowledge base for internal engineers to accelerate cross-training, unify incident response steps, and pinpoint target fields for automation.
* **Audience Profile:** Active and incoming tier analysts onboarding onto security tooling architectures.
* **Rule Evaluation Standard:** Integrated items must represent realistic threat vectors, be backed by accessible logging data sources, and present clear opportunities for automated optimization.

#### Deliverable Checklist Structure
* **Rule Identification:** Name, classification taxonomy, and threat scoring index.
* **Condition Baseline:** Detection syntax boundaries, event scope rules, and ingestion logs.
* **MITRE ATT&CK Mapping:** Tactic and technique references backed by logical execution proof.
* **Threat Profile:** Blast radius modeling covering assets, credentials, and data.
* **Triage Blueprint:** Sequential query checklists and verification steps.
* **False Positive Validation:** Clear identification parameters for authorized behavior baselines.
* **Escalation Rules:** Conditions for routing alerts up the incident response chain.
* **Automation Matrix:** High-value data fields, queries, and enrichment APIs.

---
---

## Objective 3.2: Audit Summary from Kibana

* **Audit Range & Scope:** Structured telemetry pulled straight from the Kibana SIEM and Detection Engine interfaces.
* **Monitored Windows:** Analysis ran on 10/19/26 covering rolling 7-day and 30-day baseline cycles.
* **Global Rule Footprint:** **2,120 active detection rules** deployed.
* **Aggregated Ingestion Volumetrics:**
  * **Weekly Alerts Count:** ~557,000 alerts recorded (tracking from 07:43 AM baseline).
  * **Monthly Alerts Count:** ~8,000,000 total alert fires recorded.

---
---

## Objective 3.3: Template for High-Risk Rules and Rule Guide

### Detection Rule Guide: [Name of Rule]

#### 🆔 Profile Definitions
* **Rule Name / Ingestion Type:** 
* **Severity Score Matrix:** 
* **Asset / Target Scope:** 
* **Author / Engineering Reviewer:** 
* **Version Control Lifecycle:** 

#### 🎯 Threat Significance & Purpose
* What exact behavior vector does this signature trigger on?
* Why does this technical action constitute a security risk?
* What asset structures or accounts fall inside the immediate blast radius?
* If this behavior goes unmitigated, what is the worst-case impact scenario?

#### 💻 Detection Logic & Queries
* **Plain-Language Summary:** 
* **SIEM Query Expression:** 
* **Required Log Sources:** 
* **Time Windows / Exception Logic:** 
* **Visibility Constraints (What the rule cannot see):** 

#### 🗺️ MITRE ATT&CK Structure
* **Tactic Name & ID:** 
* **Technique Name & ID:** 
* **Technical Evidence Mapping Alignment:** 

#### 🔄 Adversary Illustration Example
*[Draft an operational step-by-step model detailing how a real-world attacker executes this step. Remove the "Example" label if analyzing a confirmed past breach incident.]*

#### 🔍 Initial Investigation Steps
* What concrete event details occurred? (*Record host identities, timestamps, and client names*).
* Which process lineage, system user identity, or script execution source triggered the log entry?
* Is there a documented baseline, change order, or active authorization record that explains this event?
* What preceding system logs or subsequent behaviors are tied to this asset?

#### ⚡ Automated Enrichment & Log Strategy
* **Analyst Evaluation Question:** 
* **Lookup Search / API Target:** 
* **Target Fields & Logs Data Sources:** 
* **Analytical Outcome (What this determines):** 

* **Recommended Triage Analysis Time Window:** 
* **Data Blindspots / Inaccessible Logs:** 

#### 🟢 Benign Explanations and Validation
* **Expected Legitimate Activity:** 
* **Log Telemetry Required for Validation:** 

#### 🚨 Findings and Escalation Guidelines
* List specific system indicators that increase the alert severity level.
* List specific telemetry points that verify an authorized explanation.
* Detail the exact criteria that trigger an escalation under current operating policies.
* Outline methods for mapping high-value user tiers, critical assets, or wide network impacts.

#### 📁 Historical Context Cases
* **Past Alert Reference IDs:** 
* **Core Investigation Observations:** 
* **Incident Lifecycle Outcomes:** 
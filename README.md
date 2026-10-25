# Alert Enrichment & Triage Automation Engine

> **PORTSOC Capstone Project — Group 4**  
> An automated alert enrichment pipeline and investigation framework designed to reduce triage bottlenecks, eliminate repetitive manual workflows, and empower student security analysts.

---

## Table of Contents
1. [Project Overview & Motivation](#1-project-overview--motivation)
   - [Problem Statement](#problem-statement)
   - [Proposed Solution](#proposed-solution)
2. [Key Objectives & Success Metrics](#2-key-objectives--success-metrics)
3. [System Architecture](#3-system-architecture)
   - [High-Level Data Flow](#high-level-data-flow)
   - [Hybrid Infrastructure (AWS & ORTSOC)](#hybrid-infrastructure-aws--ortsoc)
   - [Site-to-Site IPsec Connectivity](#site-to-site-ipsec-connectivity)
4. [Core Project Components](#4-core-project-components)
   - [Track 1: TTP & Detection Rule Mapping](#track-1-ttp--detection-rule-mapping)
   - [Track 2: Kibana Pre-Query Automation](#track-2-kibana-pre-query-automation)
   - [Track 3: OSINT Enrichment Engine](#track-3-osint-enrichment-engine)
   - [Track 4: Web Analyst Dashboard](#track-4-web-analyst-dashboard)
5. [Parallel Development Strategy & Mock Data](#5-parallel-development-strategy--mock-data)
6. [API Constraints, Permissions & Fallbacks](#6-api-constraints-permissions--fallbacks)
   - [Permission Requests & Status](#permission-requests--status)
   - [Workarounds & Fallback Architecture](#workarounds--fallback-architecture)
7. [Repository Structure](#7-repository-structure)
8. [Installation & Local Setup](#8-installation--local-setup)
   - [Prerequisites](#prerequisites)
   - [Environment Configuration](#environment-configuration)
   - [Deployment Steps](#deployment-steps)
9. [Development Roadmap & Timeline (Weeks 1–7)](#9-development-roadmap--timeline-weeks-17)
10. [Team Roles & Task Allocation](#10-team-roles--task-allocation)
11. [Governance, Reporting & Peer Review](#11-governance-reporting--peer-review)
    - [Weekly Progress Reports Workflow](#weekly-progress-reports-workflow)
    - [Code Review & Pull Request Standards](#code-review--pull-request-standards)
12. [Stakeholders & Mentorship](#12-stakeholders--mentorship)
13. [References & Acknowledgments](#13-references--acknowledgments)

---

## 1. Project Overview & Motivation

### Problem Statement
In a Security Operations Center (SOC) environment such as ORTSOC, student analysts are routinely tasked with evaluating hundreds of telemetry alerts across monitored client networks. A select number of high-risk detection rules generate substantial volumes of alerts, overwhelming analysts and creating severe operational backlogs.

Investigating these alerts manually introduces high friction:
* **Context Switching & Screen Fatigue:** When an alert fires, an analyst must open 5 to 8 disparate browser tabs (such as VirusTotal, AbuseIPDB, AlienVault OTX, and WHOIS search engines) to determine whether an IP address, domain, or file hash is malicious.
* **Repetitive SIEM Querying:** Analysts must manually formulate Kibana Query Language (KQL) queries to inspect historical host behavior, network connections, and process telemetry, re-typing the same patterns for every alert instance.
* **Knowledge Fragmentation:** Junior analysts often lack clear guidelines defining the specific adversary Tactics, Techniques, and Procedures (TTPs) behind each alert rule. Without a standardized baseline explaining *what* to look for, *where* to search in the telemetry, and *how* an attacker targets ORTSOC clients, alert triage becomes inconsistent and time-consuming.

### Proposed Solution
This project delivers a multi-tiered alert enrichment and investigation automation platform that accelerates the triage lifecycle through three integrated pillars:
1. **Detection Rule Knowledge Base & TTP Mapping:** Standardized operational playbooks mapped to the MITRE ATT&CK framework for high-volume detection rules. Each guide outlines the adversarial technique, realistic attack vectors against ORTSOC clients, common false-positive baselines, and step-by-step triage guidance.
2. **Kibana Pre-Query Automation:** Pre-computed query templates and automated SIEM lookup scripts that query Kibana via API, surfacing contextual host and network logs immediately when a target alert fires.
3. **Automated OSINT Enrichment & Analyst Dashboard:** A cloud microservice hosted in an AWS Virtual Private Cloud (VPC), securely linked to ORTSOC via a Site-to-Site IPsec VPN. The microservice ingests alert parameters, queries external threat intelligence feeds (AbuseIPDB, VirusTotal, AlienVault OTX) in parallel, normalizes risk scores, and displays all telemetry, reputation data, and triage baselines on a single unified web dashboard.

---

## 2. Key Objectives & Success Metrics

The success of the project is measured against operational time savings, cognitive load reduction, and rule documentation coverage:

| Objective | Baseline Metric | Target Milestone | Verification Method |
| :--- | :--- | :--- | :--- |
| **Alert Triage Velocity** | 12–15 minutes per high-volume alert | Under 3 minutes per alert | Timed triage simulations comparing manual vs. enriched workflow |
| **Browser Tab Navigation** | 5–8 external tabs opened per alert | 1 consolidated dashboard tab | Analyst workflow observation during incident triage |
| **Rule Playbook Coverage** | Ad-hoc / informal documentation | 100% of selected high-risk rules | Completed MITRE ATT&CK-aligned playbooks in the repository |
| **Enrichment Latency** | Manual search (~300–600 seconds) | Sub-second cached lookups (< 3s uncached) | Automated latency and API turnaround profiling |
| **Threat Intelligence Breadth** | Single manual lookup (e.g., VT only) | Multi-feed correlation (IP, Hash, Domain) | Automated integration tests against VirusTotal, AbuseIPDB, and OTX |

---

## 3. System Architecture

### High-Level Data Flow

```text
┌────────────────────────┐       ┌────────────────────────┐       ┌────────────────────────┐
│  Incoming Alert Event  │ ───►  │ Rule & Artifact Parser │ ───►  │ Indicator Extraction   │
│  (Elasticsearch/Kibana)│       │ (Rule ID, Host, Time)  │       │ (IP, Domain, SHA256)   │
└────────────────────────┘       └────────────────────────┘       └───────────┬────────────┘
                                                                              │
                      ┌───────────────────────────────────────────────────────┘
                      ▼
┌────────────────────────────────────────────────────────┐
│               Site-to-Site IPsec VPN                   │
│   (AES-256-GCM / SHA-256 / IKEv2 strongSwan Tunnel)    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│           AWS Cloud VPC (Enrichment Engine)            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Local Response Cache (Redis / SQLite)            │  │
│  │ - Checks for active TTL (< 24h) before querying  │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │ (Cache Miss)             │
│                             ▼                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Asynchronous Parallel API Dispatcher             │  │
│  │ • AbuseIPDB API Client (Confidence & Reports)    │  │
│  │ • VirusTotal v3 API Client (Engines & Categories)│  │
│  │ • AlienVault OTX Client (Pulses & Threat Actors) │  │
│  │ • Rate-Limit Token Bucket (Max 4 req/min for VT) │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │                          │
│                             ▼                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Aggregation & Heuristic Scoring Engine           │  │
│  │ - Output: Consolidated Threat Score & Verdict    │  │
│  └──────────────────────────┬───────────────────────┘  │
└─────────────────────────────┼──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│           Consolidated Web Analyst Dashboard           │
│  • Visual Risk Verdict (Clean / Suspicious / Malicious)│
│  • Aggregated Reputation & Host History                │
│  • One-Click Kibana Contextual Query Deep-Links        │
│  • Rule-Specific Triage Runbook & Action Guidance      │
└────────────────────────────────────────────────────────┘
```

### Hybrid Infrastructure (AWS & ORTSOC)
* **ORTSOC On-Premises Environment:** Hosts the monitored client log aggregators, Elasticsearch cluster, and Kibana visualization layer. Alerts trigger either via automated Kibana alert actions or analyst-initiated triage queries.
* **AWS Cloud VPC:** Provides an isolated, scalable microservice hosting environment. An Amazon EC2 instance (Ubuntu 24.04 LTS) runs the strongSwan VPN daemon, a FastAPI enrichment backend, an embedded response cache, and a React/Next.js dashboard server. Outbound traffic to public OSINT APIs is routed securely through an AWS Internet Gateway.

### Site-to-Site IPsec Connectivity
Private, bidirectional communication between the AWS microservices and the ORTSOC telemetry network is maintained through a dedicated IPsec tunnel:
* **Protocol & Encryption:** IKEv2 key exchange, Diffie-Hellman Group 14 (or 19), AES-256-GCM encryption with SHA-256 data integrity checks.
* **Network Segmentation:** Security groups on the AWS EC2 instance strictly limit incoming network traffic to UDP ports 500 and 4500 from the ORTSOC gateway public IP. Internal API ports (e.g., port 8000 for FastAPI) are reachable solely over the private IPsec tunnel (`10.x.x.x` to `192.168.x.x`).

---

## 4. Core Project Components

### Track 1: TTP & Detection Rule Mapping
* **Purpose:** Serves as both an onboarding guide for new student analysts and an operational reference during active triage.
* **Target Detection Rules:** Focuses on high-frequency, high-severity detection rules responsible for alert backlogs (e.g., *Suspicious PowerShell Invocations*, *Outbound Beaconing / C2 Traffic*, *SSH/RDP Brute Force Attempts*, and *Credential Dumping via LSASS*).
* **Playbook Structure:** Each rule file contains:
  1. **MITRE ATT&CK Mapping:** Associated Tactic, Technique ID, and Sub-technique.
  2. **Adversary Mechanics:** How an attacker leverages the procedure to compromise or pivot through ORTSOC client networks.
  3. **Telemetry Checklist ("What & Where to Look"):** Exact index patterns, timestamps, hostnames, and event codes required to validate the activity.
  4. **Baseline & False-Positive Filters:** Known benign administrative tasks and expected software behaviors that trigger benign alerts.

### Track 2: Kibana Pre-Query Automation
* **Purpose:** Eliminates manual query formulation in Kibana by automatically generating targeted query strings and contextual searches.
* **Implementation Mechanism:** 
  - Standardized KQL query templates dynamically populated with the alert's entity values (`host.name`, `user.name`, `source.ip`, `process.name`).
  - Integration with Kibana's search APIs to automatically retrieve surrounding log events (15 minutes of alert firing) and package them alongside OSINT reputation findings.

### Track 3: OSINT Enrichment Engine
* **Purpose:** Ingests extracted forensic artifacts (IPv4/IPv6, domains, URLs, file hashes) and queries external intelligence feeds concurrently.
* **Integrated Feeds:**
  - **AbuseIPDB:** Gathers abuse confidence percentages, reporting host counts, ISP data, and recent community analyst comments.
  - **VirusTotal (v3):** Gathers detection engine statistics (e.g., `45/72 engines flagged as malicious`), malware family labels, and sandbox execution indicators.
  - **AlienVault OTX:** Pulls community threat pulses, associated adversary campaign tags, and threat group attributions.
* **Scoring & Heuristic Logic:** Normalizes disparate vendor ratings into a composite risk score (0 to 100) and assigns an actionable status: `Benign / Clean` (< 25), `Suspicious` (25 - 69), or `Malicious / High Risk` (>70).

### Track 4: Web Analyst Dashboard
* **Purpose:** A single-pane-of-glass user interface where analysts review incoming alerts without opening external threat intelligence tabs.
* **Key Visualizations:**
  - **Composite Threat Badge:** Immediate visual indicator of the risk verdict.
  - **Indicator Breakdown Card:** Tabs for IP reputation, domain WHOIS, and file hash hashes.
  - **One-Click Pre-Query Links:** Direct links that open Kibana with pre-filled, filtered queries.
  - **Triage Checklist:** Step-by-step guidance derived from the Track 1 rule playbooks.

---

## 5. Parallel Development Strategy & Mock Data

To ensure engineering momentum is not delayed by network access approvals or API credential issuance, development is decoupled into parallel tracks utilizing synthetic test fixtures:
* **Synthetic Alert Fixtures:** The `/services/mock-server/fixtures/` directory maintains realistic JSON alert payloads mimicking live Kibana alert exports, covering diverse scenarios (benign internal pings, known Tor exit nodes, Cobalt Strike beaconing indicators, and false-positive software updaters).
* **Decoupled Workflow:**
  - Backend developers build the regex parsers, rate-limit queues, and aggregation algorithms against mock alert payloads.
  - Frontend developers design the dashboard components and visualizations using pre-recorded multi-source API response fixtures.
  - Network and SIEM engineers configure the AWS VPC, strongSwan IPsec configurations, and Kibana query syntax independently.
* **Live Cutover:** Switching from mock data to live data requires only changing the environment flag `USE_MOCK_DATA=true` to `false` in `.env`.

---

## 6. API Constraints, Permissions & Fallbacks

### Permission Requests & Status
* **ORTSOC Access Request:** Formal request submitted for read-only Kibana API tokens and site-to-site firewall peering between the ORTSOC edge gateway and the AWS VPC.
* **OSINT Developer Credentials:** Registered free-tier community API keys for AbuseIPDB, VirusTotal, and AlienVault OTX.

### Workarounds & Fallback Architecture
In the event of administrative or technical delays in acquiring live production permissions:
1. **SIEM Query Cheat Sheets:** If direct Kibana API connectivity cannot be established through the firewall, the system generates pre-formatted, clickable Kibana URLs and copy-paste KQL strings. Analysts copy the string directly into their existing Kibana interface.
2. **Offline Log Replay:** If live ingestion is restricted, analysts export historical alert batches as JSON/CSV files, which are processed through the enrichment microservice locally.
3. **Strict Rate-Limit Safeguards:** To honor free API quotas (e.g., VirusTotal's strict limit of 4 requests/minute and AbuseIPDB's 1,000 requests/day):
   - A local caching layer (Redis or SQLite) enforces a 24-hour TTL on IP reputation queries and a 30-day TTL on file hashes.
   - An asynchronous token-bucket queue serializes outbound calls, preventing HTTP 429 quota exhaustion errors.

---

## 7. Repository Structure

```text
.
├── .github/
│   └── workflows/              # GitHub Actions CI/CD pipelines (testing and linting)
├── docs/
│   ├── architecture/           # Network architecture, IPsec topologies, data flow
│   ├── playbooks/              # Detection rule & MITRE ATT&CK TTP guides
│   └── setup/                  # Step-by-step VPN and deployment runbooks
├── infrastructure/
│   ├── terraform/              # AWS VPC, EC2 instance, and security group definitions
│   └── ipsec/                  # strongSwan configurations (ipsec.conf, ipsec.secrets)
├── services/
│   ├── enrichment-backend/     # FastAPI Python OSINT microservice
│   │   ├── clients/            # API clients (AbuseIPDB, VirusTotal, AlienVault OTX)
│   │   ├── parsers/            # Regex extraction and RFC 1918 filtering modules
│   │   └── scoring/            # Threat score heuristic normalization engine
│   ├── frontend-dashboard/     # React / Next.js web application for analysts
│   └── mock-server/            # Synthetic alert generator and recorded API fixtures
├── Progress Reports/
│   ├── Week 1/
│   ├── Week 2/
│   ├── Week 3/
│   ├── Week 4/                 # Individual progress reports (.docx) and Consolidated weekly team progress report
│   ├── Week 5/
│   ├── Week 6/
│   └── Week 7/
├── tests/
│   ├── test_parsers.py         # Unit tests for IOC regex extraction
│   ├── test_rate_limiter.py    # Unit tests for token bucket queueing
│   └── test_scoring.py         # Tests for multi-source risk score computation
├── .env.example                # Sample environment configuration template
├── docker-compose.yml          # Container configuration for backend, cache, and UI
└── README.md                   # Project documentation and developer guide
```

---

## 8. Installation & Local Setup

### Prerequisites
* **Runtime Environments:** Python 3.11+, Node.js 20+ (LTS), and Docker Engine 24+ with Docker Compose.
* **Cloud & Infrastructure:** AWS CLI configured with appropriate credentials for VPC/EC2 provisioning.
* **API Keys:** Community developer API keys for AbuseIPDB, VirusTotal, and AlienVault OTX.

### Environment Configuration
1. Clone the repository and navigate to the project root:
   ```bash
   git clone https://github.com/your-org/alert-enrichment.git
   cd alert-enrichment
   ```
2. Copy the sample environment file:
   ```bash
   cp .env.example .env
   ```
3. Populate `.env` with your active keys and network parameters:
   ```ini
   # Operating Mode
   USE_MOCK_DATA=true
   ENVIRONMENT=development

   # External Threat Intelligence APIs
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ALIENVAULT_OTX_KEY=your_alienvault_otx_key_here

   # Site-to-Site VPN & Network
   PORTSOC_GATEWAY_IP=198.51.100.1
   PORTSOC_INTERNAL_SUBNET=192.168.10.0/24
   AWS_VPC_SUBNET=10.0.1.0/24

   # Caching & Rate Limiting
   CACHE_TTL_IP_SECONDS=86400
   CACHE_TTL_HASH_SECONDS=2592000
   VT_RATE_LIMIT_PER_MINUTE=4
   ```

### Deployment Steps

#### Option A: Running with Docker Compose (Recommended)
Launch the entire stack (FastAPI backend, Redis cache, Next.js frontend, and mock server) in isolated containers:
```bash
docker-compose up --build -d
```
* **Frontend Dashboard:** `http://localhost:3000`
* **Enrichment API Docs (Swagger):** `http://localhost:8000/docs`
* **Mock Alert Stream:** `http://localhost:8000/api/mock/alerts`

#### Option B: Running Services Manually for Development
1. **Start the Backend Service:**
   ```bash
   cd services/enrichment-backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```
2. **Start the Frontend Dashboard:**
   ```bash
   cd services/frontend-dashboard
   npm install
   npm run dev
   ```

---

## 9. Development Roadmap & Timeline (Weeks 1–7)

The project follows a 7-week development plan, with two 2-person engineering sub-teams executing deliverables in parallel:

| Week | Milestone & Focus Area | Primary Deliverables & Objectives |
| :---: | :--- | :--- |
| **W1** | **VPC Deployment & API Blueprint** | Stand up AWS VPC, subnets, route tables, and EC2 gateway. Register OSINT community accounts and document API response schemas and rate limits. |
| **W2** | **Site-to-Site VPN & Ingestion Listener** | Configure strongSwan IPsec tunnel with ORTSOC gateway; verify bidirectional routing. Implement the backend alert payload listener. |
| **W3** | **IOC Extraction & Entity Parsing** | Build regex parsing routines for IPv4/IPv6, FQDNs, URLs, and hashes. Implement RFC 1918 filtering to omit private internal addresses. |
| **W4** | **IP Reputation & Abuse Clients** | Build AbuseIPDB and AlienVault OTX client integrations; extract abuse scores, country data, and threat pulse campaign tags. |
| **W5** | **File/Domain Lookups & Caching** | Implement VirusTotal v3 client for domains and hashes. Deploy Redis/SQLite cache with TTLs and token-bucket rate limiting. |
| **W6** | **Unified Scoring & Dashboard UI** | Develop normalized JSON schema and heuristic risk engine. Build web dashboard displaying threat verdicts and contextual Kibana queries. |
| **W7** | **E2E Validation, SOPs & Final Expo** | Execute end-to-end replay tests with historical alert batches. Author the Analyst Operating Runbook and finalize presentation materials. |

---

## 10. Team Roles & Task Allocation

The project is executed by a 6-person team organized into three parallel 2-person tracks:

| Team Member                 | Capstone Role | Sub-Team / Track | Core Responsibilities |
| :---                        | :---                  | :---                                    | :---                                  |
| **Almog Danziger**          | Project Manager (PM)  | **OSINT Integration & Infrastructure**  | Project coordination, AWS VPC setup Site-to-Site IPsec VPN tunnel, API integrations. |
| **Abderrahmane Rhandouri**  | Team Member (TM 5)    | **OSINT Integration & Infrastructure**  | Entity extraction regex, API rate-limiting/caching, threat scoring engine, AWS microservice. |
| **Julio Jimenez**           | Team Member (TM 1)    | **TTP Mapping & Rule Documentation**    | Rule auditing, MITRE ATT&CK alignment, investigation questionnaires, baseline guides. |
| **Jeremy Shin**             | Team Member (TM 3)    | **TTP Mapping & Rule Documentation**    | False positive analysis, adversary procedure breakdown, Unified Analyst Runbook drafting. |
| **Drake Vickers**           | Team Member (TM 2)    | **Kibana Pre-Query Automation**         | Kibana API access requirements, field/index mapping, query formulation for target rules. |
| **Marco Larios**            | Team Member (TM 4)    | **Kibana Pre-Query Automation**         | Pre-query automation script, alert result formatting, historical alert regression testing. |

---

## 11. Governance, Reporting & Peer Review

### Weekly Progress Reports Workflow
To ensure consistent accountability across the academic term:
1. Every team member writes an **Individual Progress Report** detailing achievements from the current week, goals for next week, and any encountered roadblocks.
2. Reports must be saved as standard `.docx` files and pushed to the repository by **Saturday at 11:59 PM**:
   ```text
   Progress Reports/Week X/<onid>_WeekX_Report.docx
   ```
3. The Project Lead compiles the individual submissions into a unified **Weekly Team Progress Report** stored in `/Progress Reports/Weel X/` for course and sponsor submission.

### Code Review & Pull Request Standards
* **Branch Strategy:** Work occurs on topic branches (`feature/feature-name` or `fix/issue-name`) branched off `main`.
* **Pull Request Requirements:**
  - Every PR must pass automated linting and unit test suites.
  - At least one peer review approval is required before merging.
  - No secrets, credentials, or API tokens may be committed; all configuration must reference `.env`.

---

## 12. Stakeholders & Mentorship
* **Project Sponsor:** Director of ORTSOC (Oregon State University Regional Cybersecurity Operations Center).
* **Technical Mentors:** Senior SOC Analysts and Engineering Advisors at ORTSOC.
* **Academic Institution:** Oregon State University, School of Electrical Engineering and Computer Science (EECS) — Senior Capstone Program.

---

## 13. References & Acknowledgments
* [MITRE ATT&CK Matrix for Enterprise](https://attack.mitre.org/)
* [AbuseIPDB API v2 Documentation](https://docs.abuseipdb.com/)
* [VirusTotal v3 REST API Overview](https://developers.virustotal.com/reference/overview)
* [AlienVault Open Threat Exchange (OTX) API Reference](https://otx.alienvault.com/api)
* [Elasticsearch & Kibana Query Language (KQL) Documentation](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
* [strongSwan IPsec Architecture & Documentation](https://docs.strongswan.org/)
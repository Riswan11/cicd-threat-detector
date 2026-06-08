# CI/CD Threat Detection Pipeline
An AI-powered security scanner that automatically detects threats, anomalies, and leaked secrets in CI/CD pipelines. Built as a portfolio project while transitioning into a Security Engineering / Threat Detection role.
Every finding is enriched with MITRE ATT&CK technique mappings, a quantitative risk score, lifecycle state tracking, and SARIF 2.1.0 output for enterprise SIEM ingestion — validated against a suite of simulated attack scenarios.

What it does
Every time code is pushed or a pull request is opened, this pipeline automatically:

Scans all source files for leaked API keys, passwords, tokens, and credentials
Analyzes pipeline behavior using AI to detect anomalies no regex rule could catch
Maps every finding to a MITRE ATT&CK technique with tactic, severity, and confidence
Calculates a risk score (0-100) and makes an independent policy decision (BLOCK/WARN/PASS)
Generates SARIF 2.1.0 output for ingestion into GitHub, Azure DevOps, and Microsoft Sentinel
Routes findings to the right team automatically via CODEOWNERS
Blocks the PR from merging if critical threats or zero-tolerance tactics are detected
Sends a Teams alert with a detailed findings card for the security team


Why I built this
Most CI/CD pipelines treat security as an afterthought — a single SAST tool bolted on at the end. Real-world breaches like the XZ Utils supply chain attack (2024), the Travis CI secrets leak (2021), and the CircleCI environment compromise (2023) all happened because pipelines lacked behavioral detection. They had rules, but no reasoning.
This project explores what happens when you give a pipeline the ability to reason about security context — not just match patterns, but understand what a suspicious commit looks like. It also validates that reasoning against simulated attack scenarios to prove the detections actually work.

Architecture
Every PR / push to main
        │
        ▼
┌──────────────────────────────────────────┐
│              STAGE 1: Scan               │
│                                          │
│  secrets_scanner.py  ← regex + entropy   │
│  ai_analyzer.py      ← behavioral AI     │
│  mitre_mapper.py     ← ATT&CK enrichment │
│  sarif_converter.py  ← SARIF 2.1.0       │
│                                          │
│  Outputs: security-reports/              │
└────────────────┬─────────────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
┌──────────────┐   ┌──────────────┐
│   STAGE 2    │   │   STAGE 3    │
│   Report     │   │    Gate      │
│              │   │              │
│ reporter.py  │   │  gate.py     │
│              │   │              │
│ Teams alert  │   │ Exits 1 on   │
│ on HIGH+     │   │ BLOCK →      │
│              │   │ PR blocked   │
└──────────────┘   └──────────────┘

Detection modules
detection/secrets_scanner.py
Scans every source file for leaked secrets using two techniques:
Pattern matching — regex rules for 15+ known secret formats:

Cloud provider keys (Azure Storage connection strings, SAS tokens, AWS access keys)
API tokens (GitHub PATs, Slack bot tokens, Stripe live keys, OpenAI keys)
Private keys and certificates (RSA, PGP, generic)
Database connection strings with embedded credentials
Basic auth credentials embedded in URLs

Shannon entropy detection — catches secrets that don't match any known pattern. Real API keys have high randomness (~5 bits/char). Normal code strings don't. Any assignment like api_key = "XXXX" where the value has entropy above 4.5 bits/char gets flagged as a probable secret.
Reports are redacted — findings show ghp_Ab...cdef instead of the full token, so the report itself never becomes a secrets leak.
detection/ai_analyzer.py
Collects pipeline context and sends it to an AI model (Claude / Azure OpenAI GPT-4o) for behavioral threat analysis. Detects things no regex can:

Commits at unusual hours (potential insider threat or account compromise)
Dependency file changes (supply chain attack vector — how XZ Utils was compromised)
Large code additions to security-critical paths without review
Sensitive file changes (auth, crypto, pipeline config, IAM policies)
Permission scope creep (pipeline requiring new elevated access)
Obfuscated code or unexpected binary files

The AI returns structured JSON findings with severity ratings, descriptions, evidence, and remediation recommendations. Supports both Anthropic Claude and Azure OpenAI backends via AI_BACKEND environment variable.
detection/mitre_mapper.py
Enriches every finding with MITRE ATT&CK context and produces a quantitative risk score:
ATT&CK enrichment — maps each finding to a technique ID, tactic, description, and reference URL:
json{
  "technique_id": "T1098.003",
  "technique": "Additional Cloud Roles",
  "tactic": "Persistence / Privilege Escalation",
  "url": "https://attack.mitre.org/techniques/T1098/003/"
}
Per-finding confidence — severity measures impact if real, confidence measures certainty it's real (HIGH/MEDIUM/LOW). Gate logic uses both:

BLOCK if severity HIGH + confidence HIGH
WARN if severity HIGH + confidence LOW

Risk score (0-100) — weighted combination of severity counts, MITRE technique diversity, high-risk tactic presence, and clean signal reduction.
Policy decision — separated from risk score so the reason is always explicit:
json"risk_score": { "score": 36, "rating": "MEDIUM" },
"policy": {
  "decision": "BLOCK",
  "mode": "hard_rule",
  "reasons": ["Credential Access is a zero-tolerance policy violation"]
}
Finding lifecycle — every finding has a status block for vulnerability management:
json"status": {
  "state": "OPEN",
  "first_detected": "2026-06-03T02:56:05Z",
  "sla_days": 30,
  "assigned_to": null
}
States: OPEN → ACKNOWLEDGED → SUPPRESSED / FALSE_POSITIVE → RESOLVED
CODEOWNERS routing — findings are automatically assigned to the owning team based on which file was flagged:
detection/secrets_scanner.py  →  security-engineering-team
requirements.txt              →  platform-security-team
.pipelines/*                  →  devsecops-team
detection/sarif_converter.py
Converts enriched findings into SARIF 2.1.0 format for enterprise platform integration:

Rules — one per ATT&CK technique, with markdown help linking to MITRE
Results — one per finding, with severity level, file location, and fix suggestions
Suppressions — findings marked SUPPRESSED/FALSE_POSITIVE are hidden in consumer UIs
security-severity — CVSS-style 0-10 score so GitHub ranks alerts consistently with Dependabot

Compatible with: GitHub Advanced Security, Azure DevOps scan results, VS Code SARIF Viewer, Microsoft Defender for DevOps, Splunk, Microsoft Sentinel.
detection/gate.py
Reads findings and enforces security policy with multiple blocking conditions:

Risk score ≥ 80 → BLOCK
TA0006 Credential Access tactic detected → BLOCK (zero-tolerance)
Supply chain technique (T1195) detected → BLOCK
Severity HIGH + confidence HIGH → BLOCK
Severity HIGH + confidence LOW → WARN

detection/reporter.py
Formats findings into a Microsoft Teams Adaptive Card with severity color coding, each finding with its recommendation, risk factors, and pipeline metadata.

Attack simulation & detection validation
The tests/attack-samples/ folder contains deliberately malicious artifacts used to validate every detection module:
tests/
├── run_detection_tests.sh          # Full validation suite (10/10 passing)
└── attack-samples/
    ├── secrets/
    │   ├── aws_key_leak.py         # T1552.001 — AWS key hardcoded in source
    │   ├── github_token_leak.env   # T1552.001 — GitHub PAT in .env file
    │   └── azure_storage_leak.py   # T1552.001 — Azure Storage connection string
    ├── supply_chain/
    │   ├── malicious_requirements.txt  # T1195.002 — typosquatted packages
    │   └── malicious_package.json      # T1195.002 — postinstall exfiltration
    ├── privilege_escalation/
    │   └── pipeline_rbac_expansion.yml # T1098.003 — Owner role granted to pipeline
    └── behavioral/
        └── suspicious_commit_context.json  # T1098 — off-hours commit, sensitive files
Running the suite:
bashchmod +x tests/run_detection_tests.sh
./tests/run_detection_tests.sh
Validation result: 10/10 tests passing. One real detection gap was found and fixed during validation — the Azure Storage connection string regex required exactly 86 characters but the test credential was 64. Updated to {40,} to match real-world key lengths.
Real incidents each sample maps to: Samsung (2022), XZ Utils (2024), UA-Parser-JS (2021), SolarWinds (2020).

Tech stack
ComponentTechnologyPipelineAzure DevOps (azure-pipelines.yml)AI analysisClaude API (Anthropic) / Azure OpenAI GPT-4oThreat intelligenceMITRE ATT&CK v14Output formatSARIF 2.1.0Secrets storageAzure Key VaultAlertingMicrosoft Teams (Adaptive Cards webhook)Ownership routingCODEOWNERSLanguagePython 3.11

Project structure
cicd-threat-detector/
├── .pipelines/
│   └── security-scan.yml           # Azure DevOps pipeline — 3 stages
├── detection/
│   ├── secrets_scanner.py          # Pattern + entropy secrets detection
│   ├── ai_analyzer.py              # AI behavioral threat analysis
│   ├── mitre_mapper.py             # ATT&CK enrichment, risk score, policy
│   ├── sarif_converter.py          # SARIF 2.1.0 output
│   ├── gate.py                     # Pipeline enforcement gate
│   └── reporter.py                 # Teams alert sender
├── tests/
│   ├── run_detection_tests.sh      # Detection validation suite
│   └── attack-samples/             # Simulated attack artifacts
│       ├── secrets/
│       ├── supply_chain/
│       ├── privilege_escalation/
│       └── behavioral/
├── CODEOWNERS                      # Finding ownership routing rules
├── requirements.txt
└── README.md

Running locally
bash# Install dependencies
pip3 install -r requirements.txt

# Run secrets scanner
python3 detection/secrets_scanner.py --path . --output security-reports/secrets.json

# Run AI analyzer (requires API key)
export ANTHROPIC_API_KEY="your-key-here"
python3 detection/ai_analyzer.py \
  --build-id "local-001" \
  --branch "main" \
  --commit "HEAD" \
  --output "security-reports/ai-findings.json"

# Enrich with MITRE ATT&CK + risk score + policy
python3 detection/mitre_mapper.py \
  --findings security-reports/ai-findings.json \
  --output security-reports/ai-findings-mapped.json

# Generate SARIF output
python3 detection/sarif_converter.py \
  --findings security-reports/ai-findings-mapped.json \
  --output security-reports/results.sarif

# Check gate
python3 detection/gate.py \
  --findings security-reports/ai-findings-mapped.json \
  --threshold CRITICAL

# Run detection validation suite
./tests/run_detection_tests.sh

Pipeline variables required
Set these as secret variables in Azure DevOps (Pipelines → Variables):
VariableDescriptionANTHROPIC_API_KEYAnthropic API key for Claude analysisAZURE_OPENAI_ENDPOINTAzure OpenAI endpoint (if using Azure backend)AZURE_OPENAI_API_KEYAzure OpenAI key (if using Azure backend)TEAMS_WEBHOOK_URLIncoming webhook URL for Teams alerts
Switch AI backends:
bashAI_BACKEND="anthropic"      # default — Claude API
AI_BACKEND="azure_openai"   # production — Azure OpenAI GPT-4o

Sample output
json{
  "findings": [{
    "severity": "MEDIUM",
    "confidence": "HIGH",
    "title": "New credential handling dependencies introduced",
    "mitre": {
      "technique_id": "T1555",
      "technique": "Credentials from Password Stores",
      "tactic": "Credential Access",
      "url": "https://attack.mitre.org/techniques/T1555/"
    },
    "ownership": {
      "service": "root",
      "file": "requirements.txt",
      "repo_owner": "platform-security-team"
    },
    "status": {
      "state": "OPEN",
      "sla_days": 30,
      "first_detected": "2026-06-03T02:56:05Z"
    }
  }],
  "risk_score": { "score": 36, "rating": "MEDIUM" },
  "policy": {
    "decision": "BLOCK",
    "mode": "hard_rule",
    "reasons": ["Credential Access is a zero-tolerance policy violation"]
  }
}

What I learned building this

Detection engineering fundamentals — signature-based detection (regex) vs behavioral detection (AI), and why production security tools need both
MITRE ATT&CK framework — mapping findings to technique IDs, understanding the difference between T1098.003 (Additional Cloud Roles) and T1552.007 (Container API) for cloud privilege expansion
Detection validation — building attack simulation samples and running them against detection logic to find real gaps; found and fixed an Azure Storage regex gap through this process
Risk scoring architecture — separating threat measurement (risk score) from policy enforcement (BLOCK/WARN/PASS) so blocking decisions are always explicitly justified
Vulnerability management — finding lifecycle states, SLA-based prioritization, CODEOWNERS-driven ownership routing
SARIF 2.1.0 — producing enterprise-compatible output with ATT&CK rule mappings and CVSS-style security-severity scores
Supply chain attack vectors — XZ Utils, typosquatting, postinstall script exfiltration, how dependency tampering works
Prompt engineering for security — structuring context for an AI model to reason about threats consistently and return parseable structured output
Secrets hygiene — Key Vault references, redacted reports, gitignored output directories, why the scan report itself can become a leak vector


References

XZ Utils supply chain attack analysis
Travis CI secrets exposure incident (2021)
CircleCI security incident (2023)
OWASP CI/CD Security Top 10
Microsoft Azure DevOps pipeline security

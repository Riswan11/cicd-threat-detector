# cicd-threat-detector
AI-powered CI/CD security scanner that detects leaked secrets, behavioral anomalies, and supply chain threats on every PR. Built with Python, Azure DevOps, and Claude AI.

CI/CD Threat Detection Pipeline An AI-powered security scanner that automatically detects threats, anomalies, and leaked secrets in CI/CD pipelines. Built as a learning project while transitioning into a Security Engineering / Threat Detection role.

What it does Every time code is pushed or a pull request is opened, this pipeline automatically:

Scans all source files for leaked API keys, passwords, tokens, and credentials Analyzes pipeline behavior using AI to detect anomalies that no regex rule could catch Blocks the PR from merging if critical threats are found Sends a Teams alert with a detailed findings report for the security team

Why I built this Most CI/CD pipelines treat security as an afterthought — a single SAST tool bolted on at the end. Real-world breaches like the XZ Utils supply chain attack (2024), the Travis CI secrets leak (2021), and the CircleCI environment compromise (2023) all happened because pipelines lacked behavioral detection. They had rules, but no reasoning. This project explores what happens when you give a pipeline the ability to reason about security context — not just match patterns, but understand what a suspicious commit looks like.

Architecture Every PR / push to main │ ▼ ┌─────────────────────────────────┐ │ STAGE 1: Scan │ │ │ │ secrets_scanner.py │ ← regex + entropy detection │ ai_analyzer.py │ ← behavioral AI analysis │ │ │ Outputs: security-reports/ │ └────────────┬────────────────────┘ │ ┌───────┴───────┐ ▼ ▼ ┌─────────┐ ┌──────────┐ │ STAGE 2 │ │ STAGE 3 │ │ Report │ │ Gate │ │ │ │ │ │reporter │ │ gate.py │ │ .py │ │ │ │ │ │ Exits 1 │ │ Teams │ │ on CRIT │ │ alert │ │ → blocks │ │ │ │ PR │ └─────────┘ └──────────┘

Detection modules detection/secrets_scanner.py Scans every source file for leaked secrets using two techniques: Pattern matching — regex rules for 15+ known secret formats:

Cloud provider keys (Azure Storage, SAS tokens, AWS access keys) API tokens (GitHub PATs, Slack bot tokens, Stripe live keys, OpenAI keys) Private keys and certificates (RSA, PGP) Database connection strings with embedded credentials Basic auth credentials embedded in URLs

Shannon entropy detection — catches secrets that don't match any known pattern. Real API keys have high randomness (~5 bits/char). Normal code strings don't. Any assignment like api_key = "XXXX" where the value has entropy above 4.5 bits/char gets flagged as a probable secret. Reports are redacted — findings show ghp_Ab...cdef instead of the full token, so the report itself never becomes a secrets leak. detection/ai_analyzer.py Collects pipeline context and sends it to an AI model (Claude / Azure OpenAI GPT-4o) for behavioral threat analysis. Detects things no regex can:

Commits at unusual hours (potential insider threat or account compromise) Dependency file changes (supply chain attack vector — how XZ Utils was compromised) Large code additions to security-critical paths without review Sensitive file changes (auth, crypto, pipeline config, IAM policies) Permission scope creep (pipeline requiring new elevated access) Obfuscated code or unexpected binary files

The AI returns structured JSON findings with severity ratings, descriptions, evidence, and remediation recommendations. detection/gate.py Reads the findings report and enforces the security policy:

CRITICAL findings → exit code 1 → pipeline fails → PR is blocked Below threshold → exit code 0 → pipeline passes → PR can merge

The gate threshold is configurable (--threshold CRITICAL/HIGH/MEDIUM). detection/reporter.py Formats findings into a Microsoft Teams Adaptive Card and sends it via webhook. The card includes severity color coding, each finding with its recommendation, risk factors, and pipeline metadata (build ID, branch, commit).

Tech stack ComponentTechnologyPipelineAzure DevOps (azure-pipelines.yml)AI analysisClaude API (Anthropic) / Azure OpenAI GPT-4oSecrets storageAzure Key VaultAlertingMicrosoft Teams (Adaptive Cards webhook)LanguagePython 3.11

Project structure cicd-threat-detector/ ├── .pipelines/ │ └── security-scan.yml # Azure DevOps pipeline definition ├── detection/ │ ├── secrets_scanner.py # Pattern + entropy secrets detection │ ├── ai_analyzer.py # AI behavioral threat analysis │ ├── gate.py # Pipeline enforcement gate │ └── reporter.py # Teams alert sender ├── security-reports/ # Scan output (gitignored) ├── requirements.txt └── README.md

Running locally bash# Install dependencies pip3 install -r requirements.txt

Run secrets scanner
python3 detection/secrets_scanner.py --path . --output security-reports/secrets.json

Run AI analyzer (requires API key)
export ANTHROPIC_API_KEY="your-key-here" python3 detection/ai_analyzer.py
--build-id "local-001"
--branch "main"
--commit "HEAD"
--output "security-reports/ai-findings.json"

Check gate (CRITICAL threshold)
python3 detection/gate.py
--findings security-reports/ai-findings.json
--threshold CRITICAL

Preview Teams alert card
python3 detection/reporter.py
--findings security-reports/ai-findings.json
--threshold MEDIUM

Pipeline variables required Set these as secret variables in Azure DevOps (Pipelines → Variables): VariableDescriptionANTHROPIC_API_KEYAnthropic API key for Claude analysisAZURE_OPENAI_ENDPOINTAzure OpenAI endpoint (if using Azure backend)AZURE_OPENAI_API_KEYAzure OpenAI key (if using Azure backend)TEAMS_WEBHOOK_URLIncoming webhook URL for Teams alerts To switch between AI backends: yaml# In pipeline YAML or as a variable: AI_BACKEND: "anthropic" # default AI_BACKEND: "azure_openai" # for production

What I learned building this

Detection engineering fundamentals — the difference between signature-based detection (regex) and behavioral detection (AI), and why production security tools need both Supply chain attack vectors — how dependency tampering works, what XZ Utils taught the industry about build-time attacks Prompt engineering for security — how to structure context for an AI model to reason about threats consistently and return parseable output Pipeline-as-security-enforcement — using exit codes, stage dependencies, and PR gates to make security blocking automatic rather than advisory Secrets hygiene — Key Vault references, redacted reports, gitignored output directories, and why the report itself can become a leak vector

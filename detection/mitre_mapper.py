"""
mitre_mapper.py
───────────────
Maps security findings to MITRE ATT&CK techniques, calculates
a quantitative risk score, produces a clean policy decision,
and adds finding lifecycle state for vulnerability management.

Four responsibilities:
  1. ATT&CK enrichment  → technique_id, tactic, url per finding
  2. Confidence scoring → certainty that threat is real (HIGH/MEDIUM/LOW)
  3. Risk score         → 0-100 measurement of threat level
  4. Policy decision    → BLOCK/WARN/PASS independent of score
  5. Lifecycle state    → OPEN/ACKNOWLEDGED/SUPPRESSED/FALSE_POSITIVE/RESOLVED

Lifecycle enables dashboards:
  Critical Findings
    ├── Open: 5
    ├── Suppressed: 2
    └── Resolved: 20

SARIF output (next module) will map:
  finding.title              → result.message.text
  finding.severity           → result.level
  finding.mitre.technique_id → result.ruleId
  finding.recommendation     → result.fixes
  finding.status.state       → result.suppressions (if SUPPRESSED)
"""

from __future__ import annotations

import json
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
# ATT&CK TECHNIQUE DEFINITIONS
# ══════════════════════════════════════════════════════════════

ATTACK_TECHNIQUES = {
    "T1552.001": {
        "technique_id": "T1552.001",
        "technique":    "Credentials in Files",
        "tactic":       "Credential Access",
        "tactic_id":    "TA0006",
        "description":  "Adversaries search for credentials stored in files — "
                        "config files, scripts, source code, or environment files.",
        "url":          "https://attack.mitre.org/techniques/T1552/001/"
    },
    "T1552.007": {
        "technique_id": "T1552.007",
        "technique":    "Container API",
        "tactic":       "Credential Access",
        "tactic_id":    "TA0006",
        "description":  "Adversaries gather credentials via container APIs — "
                        "querying metadata endpoints or environment variables "
                        "exposed through container runtime APIs.",
        "url":          "https://attack.mitre.org/techniques/T1552/007/"
    },
    "T1555": {
        "technique_id": "T1555",
        "technique":    "Credentials from Password Stores",
        "tactic":       "Credential Access",
        "tactic_id":    "TA0006",
        "description":  "Adversaries access credentials stored in dedicated "
                        "password or secret management systems like Key Vault.",
        "url":          "https://attack.mitre.org/techniques/T1555/"
    },
    "T1195.002": {
        "technique_id": "T1195.002",
        "technique":    "Compromise Software Supply Chain",
        "tactic":       "Initial Access",
        "tactic_id":    "TA0001",
        "description":  "Adversaries manipulate software before delivery — "
                        "tampering with dependencies or build tools. "
                        "Example: XZ Utils backdoor (2024).",
        "url":          "https://attack.mitre.org/techniques/T1195/002/"
    },
    "T1195.001": {
        "technique_id": "T1195.001",
        "technique":    "Compromise Software Dependencies and Development Tools",
        "tactic":       "Initial Access",
        "tactic_id":    "TA0001",
        "description":  "Adversaries compromise third-party libraries or "
                        "development tools used in the build process.",
        "url":          "https://attack.mitre.org/techniques/T1195/001/"
    },
    "T1098.003": {
        "technique_id": "T1098.003",
        "technique":    "Additional Cloud Roles",
        "tactic":       "Persistence / Privilege Escalation",
        "tactic_id":    "TA0003 / TA0004",
        "description":  "Adversaries add roles or permissions to cloud identities "
                        "to maintain access or escalate privileges. In CI/CD: "
                        "a pipeline managed identity being granted Key Vault "
                        "Secrets Officer, Contributor, or Owner beyond minimum scope.",
        "url":          "https://attack.mitre.org/techniques/T1098/003/"
    },
    "T1078": {
        "technique_id": "T1078",
        "technique":    "Valid Accounts",
        "tactic":       "Privilege Escalation",
        "tactic_id":    "TA0004",
        "description":  "Adversaries obtain and abuse credentials of existing "
                        "accounts — stolen pipeline service principals or "
                        "managed identities.",
        "url":          "https://attack.mitre.org/techniques/T1078/"
    },
    "T1609": {
        "technique_id": "T1609",
        "technique":    "Container Administration Command",
        "tactic":       "Execution",
        "tactic_id":    "TA0002",
        "description":  "Adversaries abuse container administration interfaces "
                        "to execute commands or modify pipeline definitions.",
        "url":          "https://attack.mitre.org/techniques/T1609/"
    },
    "T1611": {
        "technique_id": "T1611",
        "technique":    "Escape to Host",
        "tactic":       "Privilege Escalation",
        "tactic_id":    "TA0004",
        "description":  "Adversaries escape container isolation to gain access "
                        "to the underlying pipeline agent host.",
        "url":          "https://attack.mitre.org/techniques/T1611/"
    },
    "T1027": {
        "technique_id": "T1027",
        "technique":    "Obfuscated Files or Information",
        "tactic":       "Defense Evasion",
        "tactic_id":    "TA0005",
        "description":  "Adversaries obfuscate content — encoded scripts, "
                        "packed binaries, or minified malicious code.",
        "url":          "https://attack.mitre.org/techniques/T1027/"
    },
    "T1562.001": {
        "technique_id": "T1562.001",
        "technique":    "Disable or Modify Tools",
        "tactic":       "Defense Evasion",
        "tactic_id":    "TA0005",
        "description":  "Adversaries disable or modify security tools — including "
                        "removing pipeline security gates or scanning steps.",
        "url":          "https://attack.mitre.org/techniques/T1562/001/"
    },
    "T1098": {
        "technique_id": "T1098",
        "technique":    "Account Manipulation",
        "tactic":       "Persistence",
        "tactic_id":    "TA0003",
        "description":  "Adversaries manipulate accounts to maintain access — "
                        "modifying IAM role assignments or service connections.",
        "url":          "https://attack.mitre.org/techniques/T1098/"
    },
    "T1059": {
        "technique_id": "T1059",
        "technique":    "Command and Scripting Interpreter",
        "tactic":       "Execution",
        "tactic_id":    "TA0002",
        "description":  "Adversaries abuse scripting interpreters — injecting "
                        "shell commands into pipeline scripts.",
        "url":          "https://attack.mitre.org/techniques/T1059/"
    },
    "T1567": {
        "technique_id": "T1567",
        "technique":    "Exfiltration Over Web Service",
        "tactic":       "Exfiltration",
        "tactic_id":    "TA0010",
        "description":  "Adversaries exfiltrate data via web services — pipelines "
                        "making unexpected outbound calls to external endpoints.",
        "url":          "https://attack.mitre.org/techniques/T1567/"
    },
}


# ══════════════════════════════════════════════════════════════
# LIFECYCLE STATE
#
# Every finding has a status block that tracks it through its
# full lifecycle — from first detection to resolution.
#
# States:
#   OPEN          → newly detected, needs triage
#   ACKNOWLEDGED  → engineer has seen it, investigating
#   SUPPRESSED    → known risk, accepted by security team
#   FALSE_POSITIVE → confirmed not a real threat
#   RESOLVED      → fixed and verified
#
# Why this matters:
#   Without lifecycle state, every scan re-reports the same
#   findings forever. With it, you build dashboards that show
#   trend over time: are we fixing things faster than finding them?
#
# In production this state would be persisted in a database.
# Here we initialize all new findings as OPEN — a persistence
# layer (Azure Table Storage, Cosmos DB) would maintain state
# across pipeline runs by matching finding IDs.
# ══════════════════════════════════════════════════════════════

# Valid lifecycle states
LIFECYCLE_STATES = {
    "OPEN",
    "ACKNOWLEDGED",
    "SUPPRESSED",
    "FALSE_POSITIVE",
    "RESOLVED"
}

# Severity → SLA in days (industry standard vulnerability management)
# CRITICAL: 7  days  — active exploitation risk, urgent remediation
# HIGH:     14 days  — significant risk, prioritized sprint work
# MEDIUM:   30 days  — standard sprint cycle
# LOW:      90 days  — backlog, address when convenient
RESOLUTION_SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH":     14,
    "MEDIUM":   30,
    "LOW":      90,
}


# ══════════════════════════════════════════════════════════════
# CODEOWNERS ROUTING
#
# Automatically assigns findings to the right team based on
# which files were flagged, using the repo's CODEOWNERS file.
#
# How it works:
#   1. Read CODEOWNERS from repo root
#   2. For each finding, check which file triggered it
#   3. Match file path against CODEOWNERS patterns
#   4. Assign the owning team to the finding
#
# This means a leaked secret in /payment/checkout.py
# automatically routes to payment-platform-team, not a generic
# security queue. Findings arrive pre-triaged.
#
# Pattern matching follows GitHub CODEOWNERS rules:
#   *        → matches any file
#   /auth/*  → matches files in /auth/ directory
#   *.yml    → matches any .yml file
# ══════════════════════════════════════════════════════════════

def _load_codeowners(repo_root: str = ".") -> list[tuple[str, str]]:
    """
    Parse CODEOWNERS file into a list of (pattern, owner) tuples.
    Returns patterns in reverse order so more specific rules win.
    Silently returns empty list if CODEOWNERS doesn't exist.
    """
    import fnmatch

    codeowners_paths = [
        f"{repo_root}/CODEOWNERS",
        f"{repo_root}/.github/CODEOWNERS",
        f"{repo_root}/docs/CODEOWNERS",
    ]

    for path in codeowners_paths:
        try:
            content = Path(path).read_text()
            rules   = []
            for line in content.splitlines():
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    pattern = parts[0]
                    owner   = parts[1]  # take first owner if multiple
                    rules.append((pattern, owner))
            # Reverse so more specific (later) rules take priority
            return list(reversed(rules))
        except FileNotFoundError:
            continue

    return []


def _match_codeowners(filepath: str, rules: list[tuple[str, str]]) -> str:
    """
    Match a file path against CODEOWNERS rules.
    Returns the owning team name or 'unassigned' if no match.
    """
    import fnmatch

    if not filepath or not rules:
        return "unassigned"

    # Normalize path — remove leading ./
    filepath = filepath.lstrip("./")

    for pattern, owner in rules:
        # Strip leading / from pattern for matching
        clean_pattern = pattern.lstrip("/")

        # Direct match or glob match
        if fnmatch.fnmatch(filepath, clean_pattern):
            return owner
        # Match files inside a directory pattern (e.g. detection/*)
        if clean_pattern.endswith("/*"):
            dir_pattern = clean_pattern[:-2]
            if filepath.startswith(dir_pattern + "/"):
                return owner
        # Extension match (e.g. *.yml matches any .yml file)
        if clean_pattern.startswith("*") and fnmatch.fnmatch(filepath, clean_pattern):
            return owner

    return "unassigned"


def resolve_ownership(finding: dict, codeowners_rules: list) -> dict:
    """
    Build an ownership block for a finding by matching its
    flagged file against CODEOWNERS patterns.

    Returns:
      service      → inferred service name from file path
      repo_owner   → team from CODEOWNERS
      assigned_to  → null until manually assigned during triage
    """
    # Get the file that triggered this finding
    filepath = finding.get("file", finding.get("evidence", ""))

    # Extract just the file path from evidence strings like
    # "detection/secrets_scanner.py is a new 427-line file..."
    if filepath and " " in filepath:
        filepath = filepath.split()[0]

    # Infer service name from top-level directory
    parts   = filepath.lstrip("./").split("/")
    service = parts[0] if len(parts) > 1 else "root"

    # Match against CODEOWNERS
    repo_owner = _match_codeowners(filepath, codeowners_rules)

    return {
        "service":     service,
        "file":        filepath or "unknown",
        "repo_owner":  repo_owner,
        "assigned_to": None    # assigned during triage workflow
    }


def build_lifecycle_status(finding: dict, now: str) -> dict:
    """
    Build the initial lifecycle status block for a new finding.

    In a production system with persistence, this would check
    a database for existing state by finding ID and preserve it.
    New findings always start as OPEN.

    Fields:
      state           → current lifecycle state
      first_detected  → ISO timestamp when first seen
      last_detected   → ISO timestamp of most recent detection
      sla_days        → how many days to resolve based on severity
      overdue         → whether SLA has been breached
      assigned_to     → security engineer responsible (null until assigned)
      notes           → free-text notes from triage
    """
    severity = finding.get("severity", "LOW").upper()

    return {
        "state":          "OPEN",
        "first_detected": now,
        "last_detected":  now,
        "sla_days":       RESOLUTION_SLA_DAYS.get(severity, 90),
        "overdue":        False,   # false on first detection
        "assigned_to":    None,    # assigned during triage
        "notes":          None     # populated during investigation
    }


# ══════════════════════════════════════════════════════════════
# POLICY CONFIGURATION
# ══════════════════════════════════════════════════════════════

BLOCK_TACTICS = {
    "TA0006": "Credential Access is a zero-tolerance policy violation",
    "TA0010": "Exfiltration activity detected in pipeline context",
}

BLOCK_TECHNIQUE_PREFIXES = {
    "T1552": "Unsecured credentials technique detected",
    "T1195": "Supply chain compromise technique detected",
}

BLOCK_SCORE_THRESHOLD = 80
WARN_SCORE_THRESHOLD  = 60


# ══════════════════════════════════════════════════════════════
# CONFIDENCE SCORING
# ══════════════════════════════════════════════════════════════

def _infer_confidence(finding: dict) -> str:
    """Infer confidence level from finding characteristics."""
    finding_type = finding.get("type", "")
    evidence     = finding.get("evidence", "")
    category     = finding.get("category", "").lower()

    if finding_type == "pattern_match":
        return "HIGH"
    if finding_type == "high_entropy":
        return "MEDIUM"
    if evidence:
        evidence_richness = len(evidence.split()) > 15
        specific_data     = any(c in evidence for c in
                                ["==", "://", ".py", ".json", ".yml"])
        if evidence_richness and specific_data:
            return "HIGH"
        return "MEDIUM"
    if category in ("supply_chain", "injection"):
        return "MEDIUM"
    return "LOW"


# ══════════════════════════════════════════════════════════════
# TECHNIQUE MAPPING
# ══════════════════════════════════════════════════════════════

def _find_technique_id(finding: dict) -> str:
    """Map a finding to the most appropriate ATT&CK technique ID."""
    name     = finding.get("name", "").lower()
    category = finding.get("category", "").lower()
    desc     = finding.get("description", "").lower()
    combined = f"{name} {category} {desc}"

    # Privilege FIRST — before credential check to avoid
    # Key Vault keyword collision
    if any(k in combined for k in [
        "privilege", "escalat", "elevation", "iam", "rbac",
        "key vault secrets officer", "contributor", "owner",
        "access policy", "managed identity", "service principal",
        "permission", "role"
    ]):
        if any(k in combined for k in ["container admin", "escape", "host"]):
            return "T1611"
        if "pipeline definition" in combined:
            return "T1609"
        return "T1098.003"

    if any(k in combined for k in [
        "secret", "credential", "api key", "token", "password",
        "private key", "connection string", "access key", "sas token",
        "webhook", "entropy"
    ]):
        if any(k in combined for k in ["key vault", "password store", "vault"]):
            return "T1555"
        if any(k in combined for k in ["container api", "metadata"]):
            return "T1552.007"
        return "T1552.001"

    if any(k in combined for k in [
        "supply chain", "dependency", "package", "requirements",
        "npm", "pip", "cargo", "maven", "nuget", "pypi"
    ]):
        return "T1195.001" if any(k in combined for k in
                                  ["tool", "build tool", "compiler"]) \
               else "T1195.002"

    if any(k in combined for k in [
        "obfuscat", "encode", "base64", "inject", "backdoor",
        "malicious code", "binary"
    ]):
        return "T1027"

    if any(k in combined for k in [
        "pipeline", "workflow", "ci/cd", "build script",
        "security tool", "scanner", "gate", "modify"
    ]):
        return "T1562.001"

    if any(k in combined for k in [
        "account", "user access", "insider", "off-hours",
        "unusual time", "anomalous", "manipulation"
    ]):
        return "T1098"

    if any(k in combined for k in ["script", "command", "execution", "shell"]):
        return "T1059"

    if any(k in combined for k in [
        "exfil", "outbound", "network call", "external request"
    ]):
        return "T1567"

    fallbacks = {
        "supply_chain":   "T1195.002",
        "injection":      "T1027",
        "privilege":      "T1098.003",
        "anomaly":        "T1098",
        "insider_threat": "T1098",
        "secrets":        "T1552.001",
    }
    return fallbacks.get(category)


# ══════════════════════════════════════════════════════════════
# RISK SCORE
# ══════════════════════════════════════════════════════════════

HIGH_RISK_TACTIC_POINTS = {
    "TA0006": 15,
    "TA0001": 12,
    "TA0010": 10,
    "TA0004": 8,
    "TA0005": 6,
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    8,
    "LOW":       2,
}


def calculate_risk_score(findings: list[dict], clean_signals: list) -> dict:
    """Calculate a 0-100 risk score from enriched findings."""
    severity_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    tactics_found    = {}
    techniques_found = set()

    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        mitre        = f.get("mitre", {})
        tactic_id    = mitre.get("tactic_id", "")
        technique_id = mitre.get("technique_id", "")
        for tid in tactic_id.replace(" ", "").split("/"):
            if tid and tid != "TA0000":
                tactics_found[tid] = mitre.get("tactic", "Unknown")
        if technique_id and technique_id != "T0000":
            techniques_found.add(technique_id)

    severity_score = 0
    for sev, count in severity_counts.items():
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        if count > 0:
            severity_score += weight + (count - 1) * (weight // 2)
    severity_score = min(severity_score, 60)

    technique_score   = min(len(techniques_found) * 5, 20)
    tactic_score      = 0
    triggered_tactics = []
    for tid, points in HIGH_RISK_TACTIC_POINTS.items():
        if tid in tactics_found:
            tactic_score = max(tactic_score, points)
            triggered_tactics.append(tid)
    tactic_score    = min(tactic_score, 15)
    clean_reduction = min(len(clean_signals) * 1.25, 10)

    score = max(0, min(100, round(
        severity_score + technique_score + tactic_score - clean_reduction
    )))

    if score >= 80:   rating = "CRITICAL"
    elif score >= 60: rating = "HIGH"
    elif score >= 35: rating = "MEDIUM"
    elif score > 0:   rating = "LOW"
    else:             rating = "CLEAN"

    return {
        "score":  score,
        "rating": rating,
        "calculation": {
            "severity_score":    severity_score,
            "technique_score":   technique_score,
            "tactic_score":      tactic_score,
            "clean_reduction":   round(clean_reduction, 1),
            "critical_findings": severity_counts["CRITICAL"],
            "high_findings":     severity_counts["HIGH"],
            "medium_findings":   severity_counts["MEDIUM"],
            "low_findings":      severity_counts["LOW"],
            "mitre_techniques":  len(techniques_found),
            "high_risk_tactics": triggered_tactics,
            "clean_signals":     len(clean_signals),
        }
    }


# ══════════════════════════════════════════════════════════════
# POLICY DECISION
# ══════════════════════════════════════════════════════════════

def make_policy_decision(
    findings: list[dict],
    risk_score: dict,
    clean_signals: list
) -> dict:
    """Produce a policy decision independently of the risk score."""
    reasons          = []
    tactics_found    = set()
    techniques_found = set()

    for f in findings:
        # Skip suppressed and false positive findings
        # — they should not influence the policy decision
        state = f.get("status", {}).get("state", "OPEN")
        if state in ("SUPPRESSED", "FALSE_POSITIVE"):
            continue

        mitre        = f.get("mitre", {})
        tactic_id    = mitre.get("tactic_id", "")
        technique_id = mitre.get("technique_id", "T0000")
        for tid in tactic_id.replace(" ", "").split("/"):
            if tid and tid != "TA0000":
                tactics_found.add(tid)
        if technique_id != "T0000":
            techniques_found.add(technique_id)

    # Hard block rules
    for tactic_id, reason in BLOCK_TACTICS.items():
        if tactic_id in tactics_found:
            reasons.append(reason)
    for prefix, reason in BLOCK_TECHNIQUE_PREFIXES.items():
        if any(t.startswith(prefix) for t in techniques_found):
            if reason not in reasons:
                reasons.append(reason)
    if reasons:
        return {"decision": "BLOCK", "mode": "hard_rule", "reasons": reasons}

    # Score threshold block
    if risk_score["score"] >= BLOCK_SCORE_THRESHOLD:
        return {
            "decision": "BLOCK",
            "mode":     "score_threshold",
            "reasons":  [f"Risk score {risk_score['score']} exceeds "
                         f"block threshold of {BLOCK_SCORE_THRESHOLD}"]
        }

    # Confidence gate block
    for f in findings:
        state = f.get("status", {}).get("state", "OPEN")
        if state in ("SUPPRESSED", "FALSE_POSITIVE"):
            continue
        sev        = f.get("severity", "LOW").upper()
        confidence = f.get("confidence", "LOW").upper()
        if sev in ("HIGH", "CRITICAL") and confidence == "HIGH":
            return {
                "decision": "BLOCK",
                "mode":     "confidence_gate",
                "reasons":  [f"'{f.get('title', 'unknown')}' is "
                             f"{sev} severity with HIGH confidence"]
            }

    # Score threshold warn
    if risk_score["score"] >= WARN_SCORE_THRESHOLD:
        return {
            "decision": "WARN",
            "mode":     "score_threshold",
            "reasons":  [f"Risk score {risk_score['score']} exceeds "
                         f"warn threshold of {WARN_SCORE_THRESHOLD}"]
        }

    # Confidence gate warn
    for f in findings:
        state = f.get("status", {}).get("state", "OPEN")
        if state in ("SUPPRESSED", "FALSE_POSITIVE"):
            continue
        sev        = f.get("severity", "LOW").upper()
        confidence = f.get("confidence", "LOW").upper()
        if sev in ("HIGH", "CRITICAL") and confidence != "HIGH":
            return {
                "decision": "WARN",
                "mode":     "confidence_gate",
                "reasons":  [f"'{f.get('title', 'unknown')}' is {sev} severity "
                             f"but only {confidence} confidence — investigate"]
            }

    return {
        "decision": "PASS",
        "mode":     "clean",
        "reasons":  ["No blocking or warning conditions detected"]
    }


# ══════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════

def enrich_finding(finding: dict, now: str,
                   codeowners_rules: list = None) -> dict:
    """
    Add MITRE ATT&CK context, confidence, ownership, and lifecycle
    status to a single finding.
    """
    enriched     = dict(finding)
    technique_id = _find_technique_id(finding)

    enriched["mitre"] = ATTACK_TECHNIQUES.get(technique_id, {
        "technique_id": "T0000",
        "technique":    "Unknown Technique",
        "tactic":       "Unknown",
        "tactic_id":    "TA0000",
        "description":  "No ATT&CK mapping found for this finding type.",
        "url":          "https://attack.mitre.org/"
    })

    enriched["confidence"] = _infer_confidence(finding)

    # Ownership — routes finding to the right team via CODEOWNERS
    enriched["ownership"] = resolve_ownership(
        finding, codeowners_rules or []
    )

    # Only add status if not already present — preserves state
    # from a persistence layer on subsequent scans
    if "status" not in enriched:
        enriched["status"] = build_lifecycle_status(finding, now)

    return enriched


def enrich_report(report: dict) -> dict:
    """
    Enrich all findings with ATT&CK, confidence, lifecycle status,
    risk score, and policy decision.
    """
    now               = datetime.now(timezone.utc).isoformat()
    enriched          = dict(report)
    # Load CODEOWNERS once — pass to every finding for ownership routing
    codeowners_rules  = _load_codeowners()
    log.info(f"Loaded {len(codeowners_rules)} CODEOWNERS rules")
    enriched_findings = [
        enrich_finding(f, now, codeowners_rules)
        for f in report.get("findings", [])
    ]
    enriched["findings"] = enriched_findings

    # ATT&CK summary
    techniques_found = list({
        f["mitre"]["technique_id"]
        for f in enriched_findings
        if f.get("mitre", {}).get("technique_id") not in ("T0000", None)
    })
    tactics_found = list({
        t.strip()
        for f in enriched_findings
        for t in f.get("mitre", {}).get("tactic", "").split("/")
        if t.strip() and t.strip() not in ("Unknown", "")
    })

    enriched["mitre_summary"] = {
        "techniques_identified": techniques_found,
        "tactics_identified":    tactics_found,
        "technique_count":       len(techniques_found),
        "framework":             "MITRE ATT&CK v14",
        "framework_url":         "https://attack.mitre.org/"
    }

    # Lifecycle summary — for dashboards
    state_counts = {}
    for f in enriched_findings:
        state = f.get("status", {}).get("state", "OPEN")
        state_counts[state] = state_counts.get(state, 0) + 1

    enriched["lifecycle_summary"] = {
        "total":          len(enriched_findings),
        "by_state":       state_counts,
        "open":           state_counts.get("OPEN", 0),
        "acknowledged":   state_counts.get("ACKNOWLEDGED", 0),
        "suppressed":     state_counts.get("SUPPRESSED", 0),
        "false_positive": state_counts.get("FALSE_POSITIVE", 0),
        "resolved":       state_counts.get("RESOLVED", 0),
    }

    # Risk score and policy
    clean_signals        = report.get("clean_signals", [])
    risk_score           = calculate_risk_score(enriched_findings, clean_signals)
    enriched["risk_score"] = risk_score
    enriched["policy"]     = make_policy_decision(
        enriched_findings, risk_score, clean_signals
    )

    return enriched


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Enrich findings with MITRE ATT&CK, confidence, "
                    "lifecycle state, risk score, and policy decision"
    )
    parser.add_argument("--findings", required=True, help="Input findings JSON")
    parser.add_argument("--output",   required=True, help="Output enriched JSON")
    args = parser.parse_args()

    input_path  = Path(args.findings)
    output_path = Path(args.output)

    if not input_path.exists():
        log.error(f"Findings file not found: {input_path}")
        raise SystemExit(1)

    report   = json.loads(input_path.read_text())
    enriched = enrich_report(report)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(enriched, indent=2))

    rs = enriched["risk_score"]
    p  = enriched["policy"]
    lc = enriched["lifecycle_summary"]
    ms = enriched["mitre_summary"]

    log.info(f"Enriched    : {lc['total']} findings")
    log.info(f"Lifecycle   : Open={lc['open']} | Suppressed={lc['suppressed']} "
             f"| Resolved={lc['resolved']}")
    log.info(f"Risk score  : {rs['score']}/100 — {rs['rating']}")
    log.info(f"Decision    : {p['decision']} ({p['mode']})")
    for reason in p["reasons"]:
        log.warning(f"  ↳ {reason}")
    log.info(f"Techniques  : {ms['techniques_identified']}")
    log.info(f"Tactics     : {ms['tactics_identified']}")
    log.info(f"Report      : {output_path}")


if __name__ == "__main__":
    main()

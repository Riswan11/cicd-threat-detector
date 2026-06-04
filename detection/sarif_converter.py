"""
sarif_converter.py
──────────────────
Converts enriched findings (from mitre_mapper.py) into SARIF 2.1.0
format for ingestion by GitHub, Azure DevOps, VS Code, and enterprise
security platforms.

SARIF (Static Analysis Results Interchange Format) is an OASIS open
standard that gives every security tool a common output language.
Without SARIF, each tool needs a custom parser. With SARIF, any
compliant platform renders findings automatically — including inline
PR annotations showing exactly which line of code is affected.

Where SARIF is consumed:
  - GitHub Advanced Security   → PR annotations, security tab
  - Azure DevOps               → pipeline scan results tab
  - VS Code SARIF Viewer       → inline editor annotations
  - Microsoft Defender for DevOps → security posture dashboard
  - Splunk, Sentinel, Elastic  → SIEM ingestion

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

Usage:
  python detection/sarif_converter.py \
    --findings security-reports/ai-findings-mapped.json \
    --output   security-reports/results.sarif
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
# SEVERITY MAPPING
#
# SARIF uses four levels: error, warning, note, none
# We map our severity scale to SARIF levels.
#
# SARIF level → what Azure DevOps / GitHub does with it:
#   error   → fails the check, shown in red
#   warning → shown in yellow, doesn't fail
#   note    → informational, shown in blue
# ══════════════════════════════════════════════════════════════

SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "CLEAN":    "none",
}

# SARIF security-severity uses CVSS-style 0.0-10.0 score
# Used by GitHub to calculate security alert priority
SEVERITY_TO_SECURITY_SCORE = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "CLEAN":    0.0,
}


# ══════════════════════════════════════════════════════════════
# RULE BUILDER
#
# In SARIF, a "rule" is a reusable definition — one per detection
# type. Results reference rules by ID. This avoids repeating the
# full technique description in every result.
#
# Rule ID = ATT&CK technique ID (e.g. "T1552.001")
# This means any SARIF-consuming platform that knows ATT&CK
# can automatically enrich the finding with external context.
# ══════════════════════════════════════════════════════════════

def build_rules(findings: list[dict]) -> list[dict]:
    """
    Build SARIF rules from unique ATT&CK techniques in findings.
    One rule per unique technique ID — results reference by ruleId.
    """
    seen_techniques = {}

    for f in findings:
        mitre        = f.get("mitre", {})
        technique_id = mitre.get("technique_id", "T0000")

        if technique_id in seen_techniques:
            continue

        severity = f.get("severity", "LOW")
        security_score = SEVERITY_TO_SECURITY_SCORE.get(severity, 2.5)

        seen_techniques[technique_id] = {
            # ruleId maps to ATT&CK technique — universally understood
            "id": technique_id,

            # Short name shown in PR annotations
            "name": _to_pascal_case(mitre.get("technique", "UnknownTechnique")),

            # Full description shown in finding details
            "shortDescription": {
                "text": mitre.get("technique", "Unknown technique")
            },
            "fullDescription": {
                "text": (
                    f"{mitre.get('technique', 'Unknown')} — "
                    f"Tactic: {mitre.get('tactic', 'Unknown')} "
                    f"({mitre.get('tactic_id', 'TA0000')}). "
                    f"{mitre.get('description', '')}"
                )
            },

            # helpUri links directly to MITRE ATT&CK page
            # Security engineers click this to get full technique context
            "helpUri": mitre.get("url", "https://attack.mitre.org/"),
            "help": {
                "text": (
                    f"MITRE ATT&CK Technique: {technique_id}\n"
                    f"Tactic: {mitre.get('tactic', 'Unknown')}\n"
                    f"Reference: {mitre.get('url', 'https://attack.mitre.org/')}"
                ),
                "markdown": (
                    f"## {technique_id} — {mitre.get('technique', 'Unknown')}\n\n"
                    f"**Tactic:** {mitre.get('tactic', 'Unknown')} "
                    f"({mitre.get('tactic_id', '')})\n\n"
                    f"{mitre.get('description', '')}\n\n"
                    f"[View on MITRE ATT&CK]({mitre.get('url', 'https://attack.mitre.org/')})"
                )
            },

            # properties carries our custom metadata
            # SARIF allows arbitrary properties — used for filtering
            "properties": {
                "tags": [
                    mitre.get("tactic", "unknown").lower().replace(" / ", "-").replace(" ", "-"),
                    technique_id,
                    "ci-cd-security",
                    "mitre-attack"
                ],
                "security-severity": str(security_score),
                "tactic":            mitre.get("tactic", "Unknown"),
                "tactic_id":         mitre.get("tactic_id", "TA0000"),
            }
        }

    return list(seen_techniques.values())


def _to_pascal_case(s: str) -> str:
    """Convert 'Credentials in Files' to 'CredentialsInFiles'"""
    return "".join(w.capitalize() for w in s.replace("/", " ").split())


# ══════════════════════════════════════════════════════════════
# RESULT BUILDER
#
# A SARIF "result" is one instance of a rule firing — one finding.
# Each result references its rule by ID and adds instance-specific
# context: which file, which line, what the fix is.
# ══════════════════════════════════════════════════════════════

def build_result(finding: dict, run_index: int = 0) -> dict:
    """
    Convert a single enriched finding into a SARIF result object.
    """
    mitre        = finding.get("mitre", {})
    technique_id = mitre.get("technique_id", "T0000")
    severity     = finding.get("severity", "LOW").upper()
    confidence   = finding.get("confidence", "LOW").upper()
    status       = finding.get("status", {})
    ownership    = finding.get("ownership", {})

    # ── Message ───────────────────────────────────────────────
    # This is the text shown inline in PR annotations
    message_text = (
        f"[{severity}] {finding.get('title', 'Security finding')} — "
        f"{finding.get('description', '')[:200]}"
    )

    # ── Location ──────────────────────────────────────────────
    # SARIF locations point to specific files and line numbers.
    # We use the file from ownership block if available.
    file_path  = ownership.get("file", finding.get("file", "unknown"))
    line_number = finding.get("line", 1)

    # Skip obviously non-file strings like "azure-keyvault-secrets==4.8.0"
    if "==" in file_path or "://" in file_path:
        file_path = "requirements.txt"

    location = {
        "physicalLocation": {
            "artifactLocation": {
                "uri":       file_path,
                "uriBaseId": "%SRCROOT%"  # relative to repo root
            },
            "region": {
                "startLine": line_number if isinstance(line_number, int) else 1
            }
        },
        "logicalLocations": [
            {
                "name":            ownership.get("service", "unknown"),
                "fullyQualifiedName": file_path,
                "kind":            "module"
            }
        ]
    }

    # ── Suppressions ──────────────────────────────────────────
    # SARIF suppressions tell consumers to hide this finding.
    # Maps directly from our lifecycle state.
    suppressions = []
    state = status.get("state", "OPEN")
    if state in ("SUPPRESSED", "FALSE_POSITIVE"):
        suppressions.append({
            "kind":          "inSource",
            "status":        "accepted",
            "justification": (
                "False positive" if state == "FALSE_POSITIVE"
                else "Risk accepted by security team"
            )
        })

    # ── Fix / remediation ─────────────────────────────────────
    # SARIF fixes appear as suggested changes in code review tools
    fixes = []
    recommendation = finding.get("recommendation", "")
    if recommendation:
        fixes.append({
            "description": {
                "text": recommendation
            },
            "artifactChanges": []  # populated when specific line changes known
        })

    # ── Assemble result ───────────────────────────────────────
    result = {
        # Links this result to its rule definition
        "ruleId":    technique_id,
        "ruleIndex": run_index,

        # SARIF level drives pass/fail in CI
        "level":   SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),

        # Primary message shown in annotations
        "message": {"text": message_text},

        # Where in the codebase
        "locations": [location],

        # Remediation steps
        "fixes": fixes,

        # Lifecycle state → suppressions
        "suppressions": suppressions,

        # Our custom metadata preserved in properties
        # SIEM platforms can filter/query on these
        "properties": {
            "finding_id":    finding.get("id", "unknown"),
            "category":      finding.get("category", "unknown"),
            "severity":      severity,
            "confidence":    confidence,
            "technique_id":  technique_id,
            "tactic":        mitre.get("tactic", "Unknown"),
            "tactic_id":     mitre.get("tactic_id", "TA0000"),
            "repo_owner":    ownership.get("repo_owner", "unassigned"),
            "assigned_to":   ownership.get("assigned_to"),
            "sla_days":      status.get("sla_days", 30),
            "first_detected": status.get("first_detected", ""),
            "evidence":      finding.get("evidence", "")[:300],
        }
    }

    return result


# ══════════════════════════════════════════════════════════════
# SARIF DOCUMENT BUILDER
#
# The top-level SARIF document wraps everything in a "run" —
# one run per scanner execution. Multiple runs can exist in one
# file (e.g. secrets scan + AI scan combined).
# ══════════════════════════════════════════════════════════════

def build_sarif(report: dict) -> dict:
    """
    Convert a full enriched report into a SARIF 2.1.0 document.
    """
    findings   = report.get("findings", [])
    pipeline   = report.get("pipeline", {})
    risk_score = report.get("risk_score", {})
    policy     = report.get("policy", {})
    scanner    = report.get("scanner", "cicd-threat-detector")
    timestamp  = report.get("timestamp",
                            datetime.now(timezone.utc).isoformat())

    # Build rules first — results reference them by index
    rules   = build_rules(findings)
    rule_id_to_index = {r["id"]: i for i, r in enumerate(rules)}

    # Build results — one per finding
    results = []
    for f in findings:
        technique_id = f.get("mitre", {}).get("technique_id", "T0000")
        rule_index   = rule_id_to_index.get(technique_id, 0)
        results.append(build_result(f, rule_index))

    # ── SARIF document ────────────────────────────────────────
    sarif_doc = {
        # Required SARIF header
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",

        "runs": [
            {
                # Tool definition — who produced this SARIF
                "tool": {
                    "driver": {
                        "name":            "cicd-threat-detector",
                        "version":         "1.0.0",
                        "informationUri":  "https://dev.azure.com/riswan-security/cicd-threat-detector",
                        "organization":    "riswan-security",

                        # Rules = one per ATT&CK technique detected
                        "rules": rules,

                        # Properties on the tool itself
                        "properties": {
                            "framework":  "MITRE ATT&CK v14",
                            "scanner":    scanner,
                        }
                    }
                },

                # Invocation metadata — when and where this ran
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc":        timestamp,
                        "endTimeUtc":          datetime.now(timezone.utc).isoformat(),
                        "workingDirectory": {
                            "uri": "file:///pipeline/workspace"
                        },
                        "environmentVariables": {
                            "BUILD_ID":     pipeline.get("build_id", "unknown"),
                            "BRANCH":       pipeline.get("branch", "unknown"),
                            "COMMIT":       pipeline.get("commit", "unknown"),
                        },
                        # Risk score and policy captured in invocation
                        "properties": {
                            "risk_score":       risk_score.get("score", 0),
                            "risk_rating":      risk_score.get("rating", "UNKNOWN"),
                            "policy_decision":  policy.get("decision", "UNKNOWN"),
                            "policy_mode":      policy.get("mode", "unknown"),
                            "policy_reasons":   policy.get("reasons", []),
                        }
                    }
                ],

                # The actual findings
                "results": results,

                # Artifact index — files that were analyzed
                "artifacts": _build_artifacts(findings),

                # Summary properties on the run
                "properties": {
                    "pipeline_build_id":  pipeline.get("build_id", "unknown"),
                    "pipeline_branch":    pipeline.get("branch", "unknown"),
                    "pipeline_commit":    pipeline.get("commit", "unknown"),
                    "risk_score":         risk_score.get("score", 0),
                    "policy_decision":    policy.get("decision", "UNKNOWN"),
                    "mitre_techniques":   [
                        f.get("mitre", {}).get("technique_id", "T0000")
                        for f in findings
                    ],
                }
            }
        ]
    }

    return sarif_doc


def _build_artifacts(findings: list[dict]) -> list[dict]:
    """
    Build SARIF artifacts list from unique files in findings.
    Artifacts tell consumers which files were scanned.
    """
    seen_files = {}
    for f in findings:
        ownership = f.get("ownership", {})
        file_path = ownership.get("file", f.get("file", ""))

        # Skip non-file strings
        if not file_path or "==" in file_path or "://" in file_path:
            file_path = "requirements.txt"

        if file_path not in seen_files:
            seen_files[file_path] = {
                "location": {
                    "uri":       file_path,
                    "uriBaseId": "%SRCROOT%"
                },
                "roles": ["analysisTarget"]
            }

    return list(seen_files.values())


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Convert enriched findings to SARIF 2.1.0"
    )
    parser.add_argument("--findings", required=True,
                        help="Enriched findings JSON (from mitre_mapper.py)")
    parser.add_argument("--output",   required=True,
                        help="Output .sarif file path")
    args = parser.parse_args()

    input_path  = Path(args.findings)
    output_path = Path(args.output)

    if not input_path.exists():
        log.error(f"Findings file not found: {input_path}")
        raise SystemExit(1)

    log.info(f"Converting {input_path} to SARIF...")
    report   = json.loads(input_path.read_text())
    sarif    = build_sarif(report)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, indent=2))

    findings = report.get("findings", [])
    rules    = sarif["runs"][0]["tool"]["driver"]["rules"]
    results  = sarif["runs"][0]["results"]

    log.info(f"SARIF written     : {output_path}")
    log.info(f"Rules defined     : {len(rules)} ATT&CK techniques")
    log.info(f"Results exported  : {len(results)} findings")
    log.info(f"Schema            : SARIF 2.1.0")
    log.info(f"Ready for         : GitHub, Azure DevOps, VS Code, Sentinel")


if __name__ == "__main__":
    main()

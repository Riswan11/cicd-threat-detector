"""
secrets_scanner.py
──────────────────
Scans source files and CI/CD logs for leaked secrets, credentials,
and API keys. Uses regex pattern matching for known secret formats,
then flags ambiguous high-entropy strings for AI review.
 
Detection categories:
  - Cloud provider keys (Azure, AWS, GCP)
  - API tokens (GitHub, Slack, SendGrid, etc.)
  - Private keys and certificates
  - Connection strings and DSNs
  - Generic high-entropy strings
 
Usage:
  python detection/secrets_scanner.py \
    --path /path/to/scan \
    --output security-reports/secrets.json
"""
 
from __future__ import annotations
import re
import os
import sys
import json
import math
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
 
# ── Logging setup ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)
 
 
# ══════════════════════════════════════════════════════════════
# SECRET PATTERNS
#
# Each pattern has:
#   name        → human-readable label shown in the report
#   pattern     → regex that matches the secret
#   severity    → CRITICAL / HIGH / MEDIUM
#   description → what this secret gives an attacker
#
# WHY REGEX FIRST?
# Known secret formats are deterministic — an AWS key always
# starts with AKIA followed by 16 uppercase chars. Regex is
# fast, has zero false negatives for known formats, and doesn't
# need an API call. We use AI only for the ambiguous cases.
# ══════════════════════════════════════════════════════════════
 
SECRET_PATTERNS = [
 
    # ── Azure ────────────────────────────────────────────────
    {
        "name": "Azure Storage connection string",
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==",
        "severity": "CRITICAL",
        "description": "Full access to an Azure Storage account — read, write, delete all blobs."
    },
    {
        "name": "Azure SAS token",
        "pattern": r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=.{10,}&sig=[A-Za-z0-9%+/]{40,}",
        "severity": "CRITICAL",
        "description": "Shared Access Signature — scoped Azure resource access with expiry."
    },
    {
        "name": "Azure subscription key (Ocp-Apim)",
        "pattern": r"(?i)ocp-apim-subscription-key[\"']?\s*[:=]\s*[\"']?([a-f0-9]{32})",
        "severity": "HIGH",
        "description": "Azure API Management subscription key — grants API access."
    },
 
    # ── AWS ──────────────────────────────────────────────────
    {
        "name": "AWS access key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "description": "AWS access key — used with secret key for full API access."
    },
    {
        "name": "AWS secret access key",
        "pattern": r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}",
        "severity": "CRITICAL",
        "description": "AWS secret key — paired with access key ID for authentication."
    },
 
    # ── Generic API keys ─────────────────────────────────────
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "description": "GitHub PAT — repo access, potentially org-wide depending on scope."
    },
    {
        "name": "GitHub OAuth token",
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "description": "GitHub OAuth token — user-level GitHub access."
    },
    {
        "name": "Slack bot token",
        "pattern": r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}",
        "severity": "HIGH",
        "description": "Slack bot token — can read messages, post as the bot, access channels."
    },
    {
        "name": "Slack webhook URL",
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "severity": "HIGH",
        "description": "Slack incoming webhook — anyone with this URL can post to your channel."
    },
    {
        "name": "SendGrid API key",
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "HIGH",
        "description": "SendGrid key — send emails as your domain, bypass SPF/DKIM."
    },
    {
        "name": "Stripe secret key",
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": "CRITICAL",
        "description": "Stripe live secret key — charge cards, access customer data."
    },
    {
        "name": "OpenAI API key",
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "severity": "HIGH",
        "description": "OpenAI API key — run expensive inference billed to your account."
    },
 
    # ── Private keys & certs ─────────────────────────────────
    {
        "name": "RSA private key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "RSA private key — used to decrypt data or forge signatures."
    },
    {
        "name": "Generic private key",
        "pattern": r"-----BEGIN PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Private key — cryptographic identity compromise."
    },
    {
        "name": "PGP private key",
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "CRITICAL",
        "description": "PGP private key — decrypt PGP-encrypted messages."
    },
 
    # ── Passwords & connection strings ───────────────────────
    {
        "name": "Generic password in config",
        "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']",
        "severity": "HIGH",
        "description": "Hardcoded password found in config or code."
    },
    {
        "name": "Database connection string",
        "pattern": r"(?i)(mongodb|postgresql|mysql|sqlserver):\/\/[^:]+:[^@]+@[^\s]+",
        "severity": "CRITICAL",
        "description": "Database URL with embedded credentials — direct DB access."
    },
    {
        "name": "Basic auth in URL",
        "pattern": r"https?://[A-Za-z0-9_-]+:[A-Za-z0-9_\-!@#$%]{6,}@",
        "severity": "HIGH",
        "description": "Credentials embedded in a URL — visible in logs and history."
    },
]
 
 
# ══════════════════════════════════════════════════════════════
# FILE FILTERING
#
# We skip binary files, build artifacts, and third-party code.
# Scanning node_modules would take forever and find nothing useful.
# ══════════════════════════════════════════════════════════════
 
# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".go", ".java", ".cs", ".rb", ".php",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".sh", ".bash", ".ps1", ".tf", ".tfvars",
    ".xml", ".properties", ".gradle", ".dockerfile", ".txt", ".md"
}
 
# Directories to always skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", "bin", "obj", ".terraform", "vendor",
    ".mypy_cache", ".pytest_cache", "security-reports"
}

SKIP_FILES = {
    "secrets_scanner.py"  # exclude self — pattern definitions trigger own rules
}
 
# ══════════════════════════════════════════════════════════════
# ENTROPY CALCULATION
#
# High-entropy strings are likely secrets even when they don't
# match a known pattern. Shannon entropy measures randomness —
# a real English word has low entropy (~2-3 bits/char), a random
# API key has high entropy (~5+ bits/char).
#
# This catches secrets that don't match any known format,
# like custom internal tokens or obfuscated keys.
# ══════════════════════════════════════════════════════════════
 
def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy
 
 
def is_high_entropy_secret(value: str, min_length: int = 20, threshold: float = 4.5) -> bool:
    """
    Returns True if the string looks like a random secret.
    Threshold of 4.5 bits/char catches most secrets while
    avoiding false positives on normal code strings.
    """
    if len(value) < min_length:
        return False
    # Skip strings that are obviously not secrets
    if value.startswith("http") or " " in value:
        return False
    return shannon_entropy(value) >= threshold
 
 
# ══════════════════════════════════════════════════════════════
# CORE SCANNER
# ══════════════════════════════════════════════════════════════
 
def scan_file(filepath: Path) -> list[dict]:
    """
    Scan a single file for secrets. Returns a list of findings.
    Each finding contains the pattern name, severity, line number,
    and a REDACTED version of the match (never log the actual secret).
    """
    findings = []
 
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        log.warning(f"Could not read {filepath}: {e}")
        return findings
 
    lines = content.splitlines()
 
    for line_num, line in enumerate(lines, start=1):
 
        # ── Pattern matching ──────────────────────────────────
        for secret_def in SECRET_PATTERNS:
            match = re.search(secret_def["pattern"], line)
            if match:
                # IMPORTANT: Never log the actual secret value.
                # Redact it in the report so the report itself
                # doesn't become a secrets leak.
                matched_text = match.group(0)
                redacted = matched_text[:6] + "..." + matched_text[-4:] \
                    if len(matched_text) > 10 else "[REDACTED]"
 
                findings.append({
                    "type": "pattern_match",
                    "name": secret_def["name"],
                    "severity": secret_def["severity"],
                    "description": secret_def["description"],
                    "file": str(filepath),
                    "line": line_num,
                    "match_redacted": redacted,
                    "line_preview": line.strip()[:120]  # first 120 chars of line
                })
 
        # ── High-entropy string detection ─────────────────────
        # Look for assignment patterns like: key = "XXXX" or token: "XXXX"
        entropy_match = re.search(
            r'(?i)(?:key|token|secret|password|credential|api)[_\s]*[:=]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
            line
        )
        if entropy_match:
            candidate = entropy_match.group(1)
            if is_high_entropy_secret(candidate):
                findings.append({
                    "type": "high_entropy",
                    "name": "High-entropy string (possible secret)",
                    "severity": "MEDIUM",
                    "description": f"Entropy: {shannon_entropy(candidate):.2f} bits/char — likely a secret.",
                    "file": str(filepath),
                    "line": line_num,
                    "match_redacted": candidate[:4] + "...",
                    "line_preview": line.strip()[:120]
                })
 
    return findings
 
 
def scan_directory(root_path: Path) -> list[dict]:
    """Walk a directory tree and scan all eligible files."""
    all_findings = []
    scanned = 0
    skipped = 0

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune skip dirs in-place (modifies os.walk traversal)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            filepath = Path(dirpath) / filename

            # Skip self — pattern definitions trigger own rules
            if filename in SKIP_FILES:
                skipped += 1
                continue

            if filepath.suffix.lower() not in SCANNABLE_EXTENSIONS:
                skipped += 1
                continue

            findings = scan_file(filepath)
            all_findings.extend(findings)
            scanned += 1

    log.info(f"Scanned {scanned} files, skipped {skipped} files")
    return all_findings
 
 
# ══════════════════════════════════════════════════════════════
# REPORT BUILDER
# ══════════════════════════════════════════════════════════════
 
def build_report(findings: list[dict], scan_path: str) -> dict:
    """
    Assemble a structured JSON report from raw findings.
    This is the file that gate.py and reporter.py read downstream.
    """
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
 
    # Overall risk level = highest severity found
    if severity_counts["CRITICAL"] > 0:
        overall = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        overall = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        overall = "MEDIUM"
    else:
        overall = "LOW"
 
    return {
        "scanner": "secrets_scanner",
        "version": "1.0.0",
        "scan_path": scan_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(findings),
            "overall_severity": overall,
            "by_severity": severity_counts
        },
        "findings": findings
    }
 
 
# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
 
def main():
    parser = argparse.ArgumentParser(description="Scan for leaked secrets in source files")
    parser.add_argument("--path", required=True, help="Directory or file to scan")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    args = parser.parse_args()
 
    scan_path = Path(args.path)
    output_path = Path(args.output)
 
    if not scan_path.exists():
        log.error(f"Scan path does not exist: {scan_path}")
        sys.exit(1)
 
    log.info(f"Starting secrets scan on: {scan_path}")
 
    # Run the scan
    if scan_path.is_file():
        findings = scan_file(scan_path)
    else:
        findings = scan_directory(scan_path)
 
    # Build and write report
    report = build_report(findings, str(scan_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
 
    # Print summary
    summary = report["summary"]
    log.info(f"Scan complete — {summary['total_findings']} findings "
             f"| Overall: {summary['overall_severity']}")
    log.info(f"Report written to: {output_path}")
 
    # Exit code drives the pipeline gate:
    # 0 = clean or low findings, pipeline continues
    # 1 = CRITICAL found, pipeline fails, PR blocked
    if summary["overall_severity"] == "CRITICAL":
        log.error("CRITICAL secrets found — failing build")
        sys.exit(1)
 
    sys.exit(0)
 
 
if __name__ == "__main__":
    main()

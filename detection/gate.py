"""
reporter.py
───────────
Sends a formatted security findings alert to Microsoft Teams
via an incoming webhook when findings meet or exceed the threshold.
 
Teams webhooks accept an Adaptive Card payload — a structured
JSON format that renders as a rich card in the Teams channel.
 
Usage:
  python detection/reporter.py \
    --findings security-reports/ai-findings.json \
    --threshold HIGH
"""
 
from __future__ import annotations
 
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
 
try:
    import requests
except ImportError:
    print("requests not installed. Run: pip3 install requests")
    sys.exit(1)
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)
 
SEVERITY_ORDER  = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_COLORS = {
    "CRITICAL": "attention",   # red in Teams
    "HIGH":     "warning",     # orange
    "MEDIUM":   "accent",      # blue
    "LOW":      "good",        # green
    "CLEAN":    "good"
}
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "CLEAN":    "✅"
}
 
 
def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.index(s.upper()) if s.upper() in SEVERITY_ORDER else 0
 
 
def build_teams_card(report: dict) -> dict:
    """
    Build a Teams Adaptive Card payload from the findings report.
 
    Adaptive Cards are a JSON schema for rich UI in Teams.
    The card shows: overall severity, summary, each finding,
    and remediation recommendations.
 
    Teams webhook docs:
    https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
    """
    assessment = report.get("threat_assessment", {})
    findings   = report.get("findings", [])
    pipeline   = report.get("pipeline", {})
 
    overall  = assessment.get("overall_severity", "LOW").upper()
    summary  = assessment.get("summary", "No summary available")
    color    = SEVERITY_COLORS.get(overall, "accent")
    emoji    = SEVERITY_EMOJI.get(overall, "⚠️")
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
 
    # ── Header facts ──────────────────────────────────────────
    facts = [
        {"title": "Build ID",  "value": str(pipeline.get("build_id", "unknown"))},
        {"title": "Branch",    "value": str(pipeline.get("branch",   "unknown"))},
        {"title": "Commit",    "value": str(pipeline.get("commit",   "unknown"))},
        {"title": "Scanned",   "value": ts},
        {"title": "Findings",  "value": str(len(findings))},
    ]
 
    # ── Build card body ───────────────────────────────────────
    body = [
        # Title block
        {
            "type": "TextBlock",
            "text": f"{emoji} CI/CD Security Alert — {overall}",
            "weight": "Bolder",
            "size": "Large",
            "color": color
        },
        # Summary
        {
            "type": "TextBlock",
            "text": summary,
            "wrap": True,
            "color": "Default"
        },
        # Divider
        {"type": "TextBlock", "text": "---", "separator": True},
        # Pipeline metadata
        {
            "type": "FactSet",
            "facts": facts
        }
    ]
 
    # ── Add each finding as a block ───────────────────────────
    if findings:
        body.append({
            "type": "TextBlock",
            "text": "Findings",
            "weight": "Bolder",
            "size": "Medium",
            "separator": True
        })
 
        for f in findings:
            sev   = f.get("severity", "LOW").upper()
            title = f.get("title", "Unknown")
            desc  = f.get("description", "")[:200]  # truncate for card
            rec   = f.get("recommendation", "")[:150]
            femoji = SEVERITY_EMOJI.get(sev, "⚠️")
 
            body.append({
                "type": "TextBlock",
                "text": f"{femoji} **[{sev}] {title}**",
                "wrap": True,
                "color": SEVERITY_COLORS.get(sev, "Default")
            })
            body.append({
                "type": "TextBlock",
                "text": desc,
                "wrap": True,
                "isSubtle": True
            })
            if rec:
                body.append({
                    "type": "TextBlock",
                    "text": f"💡 {rec}",
                    "wrap": True,
                    "isSubtle": True,
                    "color": "Accent"
                })
 
    # ── Risk factors ──────────────────────────────────────────
    risk_factors = report.get("risk_factors", [])
    if risk_factors:
        body.append({
            "type": "TextBlock",
            "text": "Risk Factors",
            "weight": "Bolder",
            "separator": True
        })
        body.append({
            "type": "TextBlock",
            "text": "\n".join(f"• {r}" for r in risk_factors[:5]),
            "wrap": True,
            "isSubtle": True
        })
 
    # ── Assemble final Adaptive Card ──────────────────────────
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body
                }
            }
        ]
    }
 
 
def send_to_teams(webhook_url: str, card: dict) -> bool:
    """POST the Adaptive Card to the Teams webhook URL."""
    try:
        response = requests.post(
            webhook_url,
            json=card,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            log.info("Teams alert sent successfully")
            return True
        else:
            log.error(f"Teams webhook returned {response.status_code}: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to send Teams alert: {e}")
        return False
 
 
def main():
    parser = argparse.ArgumentParser(description="Send security findings to Teams")
    parser.add_argument("--findings",  required=True, help="Path to ai-findings.json")
    parser.add_argument("--threshold", default="HIGH",
                        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Minimum severity to trigger an alert")
    args = parser.parse_args()
 
    # Webhook URL comes from environment (set via Key Vault in pipeline)
    import os
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "")
 
    # ── Load report ───────────────────────────────────────────
    findings_path = Path(args.findings)
    if not findings_path.exists():
        log.warning(f"Findings not found at {findings_path} — skipping alert")
        sys.exit(0)
 
    report  = json.loads(findings_path.read_text())
    overall = report.get("threat_assessment", {}).get("overall_severity", "LOW").upper()
 
    log.info(f"Overall severity: {overall} | Alert threshold: {args.threshold}")
 
    # ── Check if alert is needed ──────────────────────────────
    if severity_rank(overall) < severity_rank(args.threshold):
        log.info(f"Severity {overall} is below threshold {args.threshold} — no alert sent")
        sys.exit(0)
 
    # ── Build and send card ───────────────────────────────────
    if not webhook_url:
        log.warning("TEAMS_WEBHOOK_URL not set — printing card to stdout instead")
        card = build_teams_card(report)
        print(json.dumps(card, indent=2))
        sys.exit(0)
 
    log.info(f"Sending Teams alert for {overall} findings...")
    card    = build_teams_card(report)
    success = send_to_teams(webhook_url, card)
    sys.exit(0 if success else 1)
 
 
if __name__ == "__main__":
    main()

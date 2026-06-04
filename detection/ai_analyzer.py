"""
ai_analyzer.py
──────────────
AI-powered behavioral threat analyzer for CI/CD pipelines.
 
Unlike secrets_scanner.py which looks for known bad patterns,
this script feeds pipeline context to an AI model and asks it
to reason about what looks suspicious — behavioral anomaly
detection that no regex can replicate.
 
What it analyzes:
  - Commit metadata (author, time, branch, message)
  - Changed files (unexpected file types, sensitive paths)
  - New dependencies (supply chain risk)
  - Build duration anomalies
  - Pipeline environment signals
  - Secrets scanner findings (from previous step)
 
Supports two AI backends (set via env var AI_BACKEND):
  - "anthropic"    → Claude API  (default, easiest to start)
  - "azure_openai" → Azure OpenAI GPT-4o (production)
 
Usage:
  python detection/ai_analyzer.py \
    --build-id "12345" \
    --branch "feature/new-auth" \
    --commit "abc123" \
    --output "security-reports/ai-findings.json"
"""
 
from __future__ import annotations
 
import os
import sys
import json
import argparse
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)
 
 
# ══════════════════════════════════════════════════════════════
# CONTEXT COLLECTOR
#
# Before we can ask AI anything, we need to gather all the
# relevant pipeline context. Think of this as assembling a
# briefing document for a security analyst.
#
# In a real Azure DevOps pipeline, most of this comes from
# built-in variables like $(Build.BuildId), $(Build.SourceVersion).
# Locally we pull what we can from Git.
# ══════════════════════════════════════════════════════════════
 
def collect_git_context(commit_sha: str) -> dict:
    """
    Pull commit metadata from Git.
    Returns author, timestamp, message, and changed files.
    """
    context = {}
 
    def run_git(args: list[str]) -> str:
        try:
            result = subprocess.run(
                ["git"] + args,
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return ""
 
    # Commit author and email
    context["author_name"]  = run_git(["log", "-1", "--format=%an", commit_sha])
    context["author_email"] = run_git(["log", "-1", "--format=%ae", commit_sha])
 
    # Commit timestamp — important for detecting off-hours commits
    raw_time = run_git(["log", "-1", "--format=%ai", commit_sha])
    context["commit_time"] = raw_time
 
    # Extract hour for anomaly detection (off-hours = higher risk)
    try:
        hour = int(raw_time[11:13])
        context["commit_hour"] = hour
        context["is_off_hours"] = hour < 6 or hour > 22
    except Exception:
        context["commit_hour"] = -1
        context["is_off_hours"] = False
 
    # Commit message — look for suspicious keywords
    context["commit_message"] = run_git(["log", "-1", "--format=%s", commit_sha])
 
    # Changed files in this commit
    changed = run_git(["diff-tree", "--no-commit-id", "-r", "--name-only", commit_sha])
    context["changed_files"] = changed.splitlines() if changed else []
 
    # Total lines added/removed
    stat = run_git(["diff-tree", "--no-commit-id", "-r", "--stat", commit_sha])
    context["diff_stat"] = stat[-200:] if stat else ""  # last 200 chars
 
    return context
 
 
def collect_dependency_changes(changed_files: list[str]) -> dict:
    """
    Check if any dependency files were modified.
    Dependency changes are a major supply chain risk signal —
    the XZ Utils backdoor was introduced exactly this way.
    """
    dep_files = {
        "requirements.txt", "requirements-dev.txt",
        "package.json", "package-lock.json", "yarn.lock",
        "Pipfile", "Pipfile.lock", "poetry.lock",
        "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
        "pom.xml", "build.gradle", "*.csproj"
    }
 
    modified_deps = []
    for f in changed_files:
        filename = Path(f).name
        if filename in dep_files or filename.endswith(".csproj"):
            modified_deps.append(f)
 
    # If dependency files changed, get the actual diff for AI review
    diff_content = ""
    for dep_file in modified_deps[:3]:  # limit to first 3 to avoid huge prompts
        try:
            result = subprocess.run(
                ["git", "diff", "HEAD~1", "HEAD", "--", dep_file],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                diff_content += f"\n--- {dep_file} ---\n{result.stdout[:500]}\n"
        except Exception:
            pass
 
    return {
        "modified_dependency_files": modified_deps,
        "has_dependency_changes": len(modified_deps) > 0,
        "dependency_diff_preview": diff_content
    }
 
 
def collect_sensitive_file_changes(changed_files: list[str]) -> list[str]:
    """
    Flag changes to security-sensitive file paths.
    Changes to auth, crypto, or pipeline config deserve extra scrutiny.
    """
    sensitive_patterns = [
        "auth", "oauth", "login", "password", "credential",
        "crypto", "encrypt", "decrypt", "signing", "certificate",
        ".pipeline", "pipeline", "workflow", "ci", "cd",
        "dockerfile", "docker-compose", "helm", "terraform",
        "iam", "policy", "permission", "role", "access"
    ]
 
    flagged = []
    for f in changed_files:
        f_lower = f.lower()
        if any(pattern in f_lower for pattern in sensitive_patterns):
            flagged.append(f)
 
    return flagged
 
 
def load_secrets_findings(secrets_report_path: str) -> dict:
    """
    Load findings from the secrets scanner (previous pipeline step).
    The AI will factor these into its overall threat assessment.
    """
    try:
        p = Path(secrets_report_path)
        if p.exists():
            data = json.loads(p.read_text())
            return {
                "secrets_scan_run": True,
                "secrets_total": data.get("summary", {}).get("total_findings", 0),
                "secrets_severity": data.get("summary", {}).get("overall_severity", "LOW"),
                "secrets_findings": data.get("findings", [])[:5]  # top 5 for prompt
            }
    except Exception:
        pass
    return {"secrets_scan_run": False}
 
 
# ══════════════════════════════════════════════════════════════
# PROMPT BUILDER
#
# This is the most important part of the script. The quality
# of the AI analysis is entirely determined by the quality
# of the prompt. Key principles:
#
# 1. Give the AI a specific ROLE ("you are a security engineer")
# 2. Provide ALL relevant context in a structured format
# 3. Ask for STRUCTURED output (JSON) so we can parse it
# 4. Define the schema explicitly so output is consistent
# 5. Give examples of what to look for (few-shot guidance)
# ══════════════════════════════════════════════════════════════
 
SYSTEM_PROMPT = """You are a senior security engineer specializing in CI/CD pipeline threat detection and supply chain security. You analyze pipeline build context to identify potential security threats, anomalies, and risks.
 
Your job is to review the provided pipeline context and identify:
1. Behavioral anomalies (unusual timing, unexpected changes, suspicious patterns)
2. Supply chain risks (dependency changes, new packages, version pinning issues)
3. Privilege or permission concerns (pipeline config changes, IAM modifications)
4. Code injection risks (obfuscated code, unexpected binary files, build script changes)
5. Insider threat signals (off-hours activity, unusual commit patterns)
 
You must respond with ONLY a valid JSON object in this exact schema:
{
  "threat_assessment": {
    "overall_severity": "CRITICAL|HIGH|MEDIUM|LOW|CLEAN",
    "confidence": "HIGH|MEDIUM|LOW",
    "summary": "2-3 sentence plain English summary of findings"
  },
  "findings": [
    {
      "id": "unique string e.g. ANOMALY-001",
      "category": "anomaly|supply_chain|privilege|injection|insider_threat",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "short title",
      "description": "detailed explanation of the threat",
      "evidence": "specific data points from the context that support this finding",
      "recommendation": "concrete remediation step"
    }
  ],
  "risk_factors": ["list", "of", "contributing", "risk", "factors"],
  "clean_signals": ["list", "of", "things", "that", "look", "normal"]
}
 
If nothing suspicious is found, return overall_severity as CLEAN with an empty findings array.
Be precise — false positives erode trust in the security system. Only flag genuine concerns."""
 
 
def build_analysis_prompt(pipeline_context: dict) -> str:
    """
    Assemble all collected context into a structured prompt.
    We format it as a readable briefing document so the AI
    can reason about it naturally.
    """
    ctx = pipeline_context
    git = ctx.get("git", {})
    deps = ctx.get("dependencies", {})
    secrets = ctx.get("secrets", {})
    sensitive_files = ctx.get("sensitive_files", [])
 
    prompt = f"""Analyze this CI/CD pipeline build for security threats and anomalies.
 
## Pipeline Metadata
- Build ID: {ctx.get('build_id', 'unknown')}
- Branch: {ctx.get('branch', 'unknown')}
- Commit SHA: {ctx.get('commit', 'unknown')[:12]}
- Timestamp: {datetime.now(timezone.utc).isoformat()}
 
## Commit Information
- Author: {git.get('author_name', 'unknown')} <{git.get('author_email', 'unknown')}>
- Commit time: {git.get('commit_time', 'unknown')}
- Off-hours commit: {git.get('is_off_hours', False)}
- Commit message: {git.get('commit_message', 'none')[:200]}
 
## Changed Files ({len(git.get('changed_files', []))} total)
{chr(10).join(f'  - {f}' for f in git.get('changed_files', [])[:20])}
 
## Diff Summary
{git.get('diff_stat', 'not available')}
 
## Dependency Changes
- Dependency files modified: {deps.get('has_dependency_changes', False)}
- Modified files: {', '.join(deps.get('modified_dependency_files', [])) or 'none'}
{f"- Diff preview:{deps.get('dependency_diff_preview', '')}" if deps.get('has_dependency_changes') else ''}
 
## Sensitive File Changes
{chr(10).join(f'  - {f}' for f in sensitive_files) if sensitive_files else '  none detected'}
 
## Secrets Scanner Results (previous step)
- Scanner ran: {secrets.get('secrets_scan_run', False)}
- Total findings: {secrets.get('secrets_total', 0)}
- Overall severity: {secrets.get('secrets_severity', 'unknown')}
{f"- Top findings: {json.dumps(secrets.get('secrets_findings', [])[:3], indent=2)}" if secrets.get('secrets_total', 0) > 0 else ''}
 
Analyze the above context and return your threat assessment as JSON."""
 
    return prompt
 
 
# ══════════════════════════════════════════════════════════════
# AI BACKENDS
#
# We support two backends. The interface is identical —
# both take a prompt and return a string response.
# Swap between them with the AI_BACKEND environment variable.
# ══════════════════════════════════════════════════════════════
 
def call_anthropic(prompt: str) -> str:
    """Call Claude via Anthropic API."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    except ImportError:
        log.error("anthropic package not installed. Run: pip3 install anthropic")
        sys.exit(1)
    except KeyError:
        log.error("ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)
 
 
def call_azure_openai(prompt: str) -> str:
    """Call GPT-4o via Azure OpenAI."""
    try:
        from openai import AzureOpenAI
        client = AzureOpenAI(
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            api_version="2024-02-01"
        )
        response = client.chat.completions.create(
            model=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt}
            ],
            max_tokens=2000,
            temperature=0.1   # low temperature = more consistent, less creative
        )
        return response.choices[0].message.content
    except ImportError:
        log.error("openai package not installed. Run: pip3 install openai")
        sys.exit(1)
    except KeyError as e:
        log.error(f"Missing environment variable: {e}")
        sys.exit(1)
 
 
def call_ai(prompt: str) -> str:
    """Route to the correct AI backend based on AI_BACKEND env var."""
    backend = os.environ.get("AI_BACKEND", "anthropic").lower()
    log.info(f"Using AI backend: {backend}")
 
    if backend == "azure_openai":
        return call_azure_openai(prompt)
    else:
        return call_anthropic(prompt)
 
 
# ══════════════════════════════════════════════════════════════
# RESPONSE PARSER
#
# AI responses aren't always perfectly formatted JSON.
# We need to be defensive about parsing — extract the JSON
# block even if the model adds extra text around it.
# ══════════════════════════════════════════════════════════════
 
def parse_ai_response(raw_response: str) -> dict:
    """
    Safely parse AI response into a dict.
    Handles cases where the model wraps JSON in markdown code blocks.
    """
    text = raw_response.strip()
 
    # Strip markdown code fences if present
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()
 
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        log.warning(f"Could not parse AI response as JSON: {e}")
        # Return a safe fallback so the pipeline doesn't crash
        return {
            "threat_assessment": {
                "overall_severity": "LOW",
                "confidence": "LOW",
                "summary": "AI analysis could not be parsed. Manual review recommended."
            },
            "findings": [],
            "risk_factors": ["AI response parsing failed"],
            "clean_signals": [],
            "parse_error": str(e),
            "raw_response": raw_response[:500]
        }
 
 
# ══════════════════════════════════════════════════════════════
# REPORT BUILDER
# ══════════════════════════════════════════════════════════════
 
def build_report(ai_result: dict, pipeline_context: dict) -> dict:
    """Merge AI findings with pipeline metadata into final report."""
    return {
        "scanner": "ai_analyzer",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline": {
            "build_id": pipeline_context.get("build_id"),
            "branch": pipeline_context.get("branch"),
            "commit": pipeline_context.get("commit", "")[:12]
        },
        "threat_assessment": ai_result.get("threat_assessment", {}),
        "findings": ai_result.get("findings", []),
        "risk_factors": ai_result.get("risk_factors", []),
        "clean_signals": ai_result.get("clean_signals", [])
    }
 
 
# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
 
def main():
    parser = argparse.ArgumentParser(description="AI-powered CI/CD threat analyzer")
    parser.add_argument("--build-id",  required=True, help="Pipeline build ID")
    parser.add_argument("--branch",    required=True, help="Git branch name")
    parser.add_argument("--commit",    default="HEAD", help="Commit SHA")
    parser.add_argument("--output",    required=True, help="Output JSON report path")
    parser.add_argument("--secrets-report",
                        default="security-reports/secrets.json",
                        help="Path to secrets scanner output")
    args = parser.parse_args()
 
    log.info(f"Starting AI threat analysis — build {args.build_id} on {args.branch}")
 
    # ── Step 1: Collect all context ───────────────────────────
    log.info("Collecting pipeline context...")
    git_context  = collect_git_context(args.commit)
    dep_context  = collect_dependency_changes(git_context.get("changed_files", []))
    sensitive     = collect_sensitive_file_changes(git_context.get("changed_files", []))
    secrets_ctx  = load_secrets_findings(args.secrets_report)
 
    pipeline_context = {
        "build_id": args.build_id,
        "branch":   args.branch,
        "commit":   args.commit,
        "git":      git_context,
        "dependencies": dep_context,
        "sensitive_files": sensitive,
        "secrets":  secrets_ctx
    }
 
    # ── Step 2: Build prompt ──────────────────────────────────
    log.info("Building analysis prompt...")
    prompt = build_analysis_prompt(pipeline_context)
 
    # ── Step 3: Call AI ───────────────────────────────────────
    log.info("Sending context to AI for threat analysis...")
    raw_response = call_ai(prompt)
 
    # ── Step 4: Parse + build report ─────────────────────────
    ai_result = parse_ai_response(raw_response)
    report    = build_report(ai_result, pipeline_context)
 
    # ── Step 5: Write report ──────────────────────────────────
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
 
    # ── Step 6: Summary + exit code ──────────────────────────
    assessment = report.get("threat_assessment", {})
    severity   = assessment.get("overall_severity", "LOW")
    findings   = report.get("findings", [])
 
    log.info(f"Analysis complete — {len(findings)} findings | Overall: {severity}")
    log.info(f"Summary: {assessment.get('summary', 'none')}")
    log.info(f"Report written to: {output_path}")
 
    if severity == "CRITICAL":
        log.error("CRITICAL threat detected — failing build")
        sys.exit(1)
 
    sys.exit(0)
 
 
if __name__ == "__main__":
    main()

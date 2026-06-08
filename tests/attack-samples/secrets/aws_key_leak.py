"""
ATTACK SAMPLE: AWS Access Key Hardcoded in Source
──────────────────────────────────────────────────
Technique : T1552.001 — Credentials in Files
Tactic    : Credential Access (TA0006)
Severity  : CRITICAL

Scenario:
  A developer accidentally commits AWS credentials directly into
  source code — one of the most common real-world secret leaks.
  The Samsung breach (2022) involved exactly this pattern.

Expected detection:
  secrets_scanner.py → CRITICAL finding
  Pattern matched   : "AWS access key ID" (AKIA[0-9A-Z]{16})

DO NOT USE THESE CREDENTIALS — they are synthetic test values.
"""

import boto3

# INTENTIONALLY BAD: hardcoded AWS credentials
# A real attacker would use these to access S3, EC2, IAM etc.
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION            = "us-east-1"

def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

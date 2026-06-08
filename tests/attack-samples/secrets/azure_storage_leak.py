"""
ATTACK SAMPLE: Azure Storage Connection String Hardcoded
Technique : T1552.001 — Credentials in Files
Tactic    : Credential Access (TA0006)
Severity  : CRITICAL
"""

# INTENTIONALLY BAD: Azure Storage connection string on one line
AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=dGhpcyBpcyBhIGZha2Uga2V5IGZvciB0ZXN0aW5nIHB1cnBvc2VzIG9ubHkgZG8gbm90IHVzZQ==;EndpointSuffix=core.windows.net"

# INTENTIONALLY BAD: OpenAI API key
OPENAI_API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUV"

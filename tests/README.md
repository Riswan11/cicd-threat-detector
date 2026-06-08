Attack Simulation Samples
Deliberately malicious artifacts used to validate that each detection
module fires correctly. Every sample maps to a real-world attack
technique with a documented MITRE ATT&CK reference.
This is detection validation — the practice of proving your
detectors work before deploying them. Without validation, a detection
gap could go unnoticed until a real attack slips through.

How to use
bash# Run the full validation suite from repo root
chmod +x tests/run_detection_tests.sh
./tests/run_detection_tests.sh
Each test asserts a specific finding is produced. If a test fails,
it means a real attack using that technique would not be detected.

Sample inventory
secrets/ — Credential exposure (T1552)
FileTechniqueWhat it simulatesaws_key_leak.pyT1552.001AWS access key hardcoded in Python sourcegithub_token_leak.envT1552.001GitHub PAT committed in .env fileazure_storage_leak.pyT1552.001Azure Storage connection string in config
Real incidents: Samsung (2022) — AWS keys committed to public GitHub repo.
supply_chain/ — Dependency tampering (T1195.002)
FileTechniqueWhat it simulatesmalicious_requirements.txtT1195.002Typosquatted packages + unpinned versionsmalicious_package.jsonT1195.002npm postinstall script exfiltrating env vars
Real incidents: XZ Utils backdoor (2024), UA-Parser-JS (2021).
privilege_escalation/ — Cloud role expansion (T1098.003)
FileTechniqueWhat it simulatespipeline_rbac_expansion.ymlT1098.003Pipeline granting itself Owner role on subscription
Real incidents: SolarWinds (2020) — pipeline used to push malicious updates.
behavioral/ — Anomalous activity (T1098)
FileTechniqueWhat it simulatessuspicious_commit_context.jsonT1098Off-hours commit touching auth + pipeline + IAM files
Real incidents: Insider threat patterns observed in multiple breaches.

Adding new samples
When adding a new attack sample:

Create the file in the appropriate category folder
Add a comment block at the top documenting:

ATT&CK technique and tactic
Severity
Real-world incident reference
Expected detection


Add a test case in run_detection_tests.sh
Verify the test passes before committing


Important
These files contain synthetic credentials and malicious patterns
for testing purposes only. They are:

Not real credentials (values are example/test strings)
Not functional malware
Intentionally committed to validate detection coverage

The security-reports/ output directory is gitignored so scan
results from test runs are never committed.

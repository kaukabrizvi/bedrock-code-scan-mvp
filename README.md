# Bedrock Code Scan MVP

Diff-only code scanner invoked from GitHub Actions. Lambda calls Bedrock with a policy that focuses on input parsing and concurrency bugs and ignores `bin/**`.

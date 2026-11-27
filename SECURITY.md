# Security policy

## Supported versions

Security fixes target the current recorded edition on the default branch (`main`). Include the commit SHA in your report so the maintainer can identify the exact version. Older snapshots and unmerged branches receive no separate security updates.

## Report a vulnerability privately

Use GitHub's [private vulnerability reporting form](https://github.com/abhi0874/guardrail/security/advisories/new). Keep vulnerability details, credentials and account data out of public issues, pull requests and CI logs.

Include the affected commit, component, security boundary, expected and observed behavior, and potential impact. If you can reproduce the issue safely, include a minimal description from a local checkout using synthetic data and credentials. Keep tests within systems and accounts you have permission to use.

The maintainer will use the private report to confirm receipt, ask for clarification, assess impact and coordinate a fix. Please keep details private while we agree on a disclosure timeline. The maintainer will coordinate any public advisory and attribution with the reporter.

## Scope

This policy covers the public Guardrail MCP server, offline Scanner, recorded dashboard, and their build and CI configuration. The dashboard and recruiter walkthroughs use synthetic data. The privately operated account-enabled application and restricted backend have separate operator controls. [Deployment status](docs/DEPLOYMENT_STATUS.md)

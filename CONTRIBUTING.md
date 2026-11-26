# Contributing

Work on a topic branch and use the synthetic fixtures. Run the relevant [checks](docs/VERIFICATION.md) and describe what they cover. Keep credentials, account identifiers, private operational evidence and unapproved copied material out of commits and CI artifacts. Include the source, applicable license and notices for bundled third-party changes.

For the planned public GitHub Free repository, protect the default branch. Require pull requests and passing checks with unique names. Disable force pushes and deletions, apply protections to administrators where available, and require an approving review once a second qualified reviewer is available. A solo maintainer should record manual review and require CI until independent review is available. Use read-only workflow tokens and keep fork CI free of private secrets and caches.

Report suspected vulnerabilities privately through the channel described in [SECURITY.md](SECURITY.md).

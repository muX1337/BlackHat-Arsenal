# Catch the Flow: Securing CI/CD Workflows with Flowlyt

## Description
In March 2025, a significant supply chain attack compromised the widely-used GitHub Action `tj-actions/changed-files`, affecting over 23,000 repositories. Attackers injected malicious code that exfiltrated secrets from CI/CD runners by dumping them into workflow logs, exposing sensitive credentials like GitHub Personal Access Tokens and private RSA keys. This incident, assigned CVE-2025-30066, underscored the vulnerabilities inherent in relying on third-party actions within CI/CD pipelines.

In response to this breach, We developed "Flowlyt", a go langauge based static analysis tool designed to scan GitHub Actions workflows for malicious patterns, misconfigurations, and hardcoded secrets. Flowlyt integrates with Open Policy Agent (OPA) to enforce custom security policies, enabling organizations to proactively detect and mitigate potential threats in their CI/CD workflows.

## Code
https://github.com/harekrishnarai/flowlyt

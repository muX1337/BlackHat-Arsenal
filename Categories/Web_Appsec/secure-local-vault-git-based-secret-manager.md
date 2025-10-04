# Secure Local Vault - Git Based Secret Manager

## Description
Problem Statement:

At Companies secrets are being used across various environments for integration and authentication services. However, managing the secrets and preventing incidents from leakage of secrets have been challenging for the organisation. Existing solutions are centralised and warrants considerable code change to be implemented. Following are the problem statement to be resolved:

- To manage and secure the secrets that are currently in plain text across Git, IaC templates, and workloads.

- To implement a secrets manager that is developer friendly and reduces operational overheads.

- To develop a solution that does not expose the secrets even at the compromise of entities storing the credentials. For example, to protect our secrets from CodeCov like incidents.

Solution:

We have developed a Git based secret manager which adopts a secure and decentralised approach to managing, sharing, and storing the secrets. In this approach secrets are stored in an encrypted form in Github repositories of the teams.

Keys Principles

This implementation follows two important principles

-A developer can be allowed to add or modify secrets, however should not be allowed to view them

-An environment should have a single identity that gives access to all necessary credentials irrespective of the number of projects that are deployed.

## Code
https://github.com/hashicorp/vault

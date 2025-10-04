# ChainAlert: Alert Developers and Open Source Maintainers of Potential Supply Chain Attacks and Suspicious Package Release

## Description
Recent NPM package takeovers such as "coa" and "UAParser.js" have affected organizations by the thousands. This has amplified the need for a monitoring system to alert developers, Open Source maintainers, and the community in case of suspicious activities that might hint of an account takeover or malicious package being published.

Learning the lessons from these attacks, we have created ChainAlert, which continuously monitors new open source releases and helps minimize the damages from future attacks. ChainAlert does this by closing the time gap between takeover events to detection and mitigation. This is especially important for packages that aren't very actively maintained and there aren't many people who would notice a problem until it is too late.

In many cases, even unmaintained packages have millions of weekly downloads, making a takeover spread very fast, amplifying the risk to the community.

In this session, you will learn about:

- Recent history of NPM account takeovers and lessons learned.
- What really happens in the wild-wild-west of NPM uploads.
- Common developer bad practice that might lead to flag a release as suspicious.
- How to protect yourself and your organization with ChainAlert against possible supply chain attacks.
- How to contribute back to the community by detecting more suspicious activity.

## Code
https://github.com/Checkmarx/chainalert-github-action

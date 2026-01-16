# Patch Wednesday - Multi-Agent System for Patch Diffing

## Description
Every month, Microsoft's Patch Tuesday drops dozens of security updates encapsulated in KBs, each addressing multiple CVEs across Windows components. PatchDiffAI is a first-of-its-kind, AI-driven multi-agent framework that ingests Patch Tuesday metadata, dissects each patched CVE, and delivers a fully automated, end-to-end root-cause analysis report.

By automating the most time-consuming steps of patch triage, PatchDiffAI empowers security teams to focus on mitigation and defense, rather than manual analysis overhead.

We'll share our journey in building this AI-driven vulnerability analysis tool, highlighting the key challenges we faced and how we overcame them, ultimately achieving 86% accuracy in root-cause labeling of Patch Tuesday reports.

Attendees will gain insights into designing and coordinating multiple specialized AI agents, each with distinct roles and models, working together seamlessly - from natural language processing of vendor advisories to byte-level binary diffing.

## Code
https://github.com/akamai/patchdiff-ai

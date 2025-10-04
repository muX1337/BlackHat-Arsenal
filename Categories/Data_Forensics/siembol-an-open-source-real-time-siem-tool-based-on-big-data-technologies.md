# Siembol: An Open-Source Real-Time SIEM Tool Based on Big Data Technologies

## Description
Siembol is an in-house developed security data processing application, forming the core of an internal Security Data Platform.

Following the experience of using Splunk, and as early adopters of Apache Metron, the team needed a highly efficient, real-time event processing engine with fewer limitations and more enhanced features. With Metron now retired, Siembol hopes to give the community an evolved alternative.

Siembol improvements over Metron:
- Components for real-time alert escalation: CSIRT teams can easily create a rule-based alert from a single data source, or they can create advanced correlation rules that combine various data sources. Moreover, Siembol UI supports importing a Sigma rule into Siembol alerting.
- Ability to integrate with other systems using dedicated components and plugin architecture for easy integration with incident response tools
- Advanced parsing framework for building fault-tolerant parsers
- Enhanced enrichment component allowing for defining rules and joining enrichment tables
- Configurations and rules are defined by a modern Angular web application, with a git-based approval process
- Supports OAuth2/OIDC for authentication and authorization in Siembol UI
- Easy installation for use with prepared docker images, helm charts and quick start guide

Siembol Use Cases:
- SIEM log collection using open-source technologies
- Detection tool for discovery of leaks and attacks on infrastructure
- Real-time stream Sigma rule evaluation without the need to index logs

## Code
https://github.com/G-Research/siembol

# Dracon, Security Engineering Automation, No Code, At Your Fingertips

## Description
Dracon is an open source, Application and Cloud Security Orchestration and Correlation (ASOC) platform, empowering organisations to establish and manage comprehensive application security programs. By creating customizable pipelines, Dracon enables the execution of a wide range of security tools against any target. During a pipeline execution Dracon runs user-configured tools in parallel. Concurrently, results from each tool are deduplicated, enriched with information based on organisational or regulatory policies, compliance requirements, and more, before being forwarded to any visualisation or data processing sink.
The primary objective of Dracon is to offer a scalable and flexible framework that enables execution of arbitrary security tools on code and infrastructure while processing the results in a versatile manner. Under the hood, Dracon runs parallel user-configured security tools(Producer Stage), aggregates, and transforms the results into an internal format.
Once results are normalised, Dracon can apply user defined information enrichment. An enricher is custom code that allows users to enhance the information presented based on internal policies and compliance requirements. Out of the box, Dracon supports Deduplication, Policy and SBOM information enrichers, while writing a new enricher is made easy for the user with the help of provided libraries.
Finally, Dracon directs enriched results to a layer of user-configurable Consumers. A consumer can be any data visualisation, alerting or vulnerability management solution. This powerful, extensible platform simplifies security engineering and enables organisations to strengthen their cybersecurity posture.

## Code
https://github.com/thought-machine/dracon

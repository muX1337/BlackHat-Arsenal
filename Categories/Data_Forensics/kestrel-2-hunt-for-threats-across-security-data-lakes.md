# Kestrel 2: Hunt For Threats Across Security Data Lakes

## Description
Many organizations today leverage data lakes for organizing security data, from alerts to raw logs and telemetry. While a lot of open-source data lake technology is available like Delta Lake, OpenSearch, and Apache Iceberg, little has been explored in the open source community on how to ease threat discovery using the data. With the establishment of open schema standards like OCSF and OpenTelemetry, we are one step closer to the answer. And this summer, the Kestrel team will release Kestrel 2, which enables security professionals to hunt and investigate on top of one or multiple data lakes with native OCSF, OpenTelemetry, and STIX descriptions in huntflows.

In this session, we will debut Kestrel 2 with an example huntbook and its compiled queries side by side to give the audience an impression of what Kestrel is and what its compiler does. Next we will kick off the fun part---a blue team hunting lab. We will walk through and execute a few simple-to-advanced Kestrel hunts against multi-stage attack campaigns, which the audience can try in their copy of the lab. We will start from hunting simple MITRE techniques using logs from one source, e.g., EDR, move to hunting advanced MITRE techniques by connecting logs from multiple sources. Then, we will dive into a multi-tactic hunt using on-premise logs of an enterprise stored at one data lake and cloud application logs stored at another. We will follow attacker's lateral movement from one data lake to the other in a Kestrel hunt to reveal the entire threat and give insights on response development.

## Code
https://github.com/opencybersecurityalliance/black-hat-us-2024

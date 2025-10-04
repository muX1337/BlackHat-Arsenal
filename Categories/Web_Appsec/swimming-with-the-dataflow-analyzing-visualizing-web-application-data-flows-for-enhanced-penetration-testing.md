# Swimming with the (Data)Flow – Analyzing & Visualizing Web Application Data Flows for Enhanced Penetration Testing

## Description
Imagine pentesting a large web application with hundreds of pages and forms, as well as user roles and tenants. You discover that your chosen username is reflected in many locations inside the application, but you don't have a detailed overview. You want to test whether the chosen username is handled properly or allows for injection attacks, such as Cross-Site Scripting or Server-Site Template Injection. Now you face the challenge of finding all locations where your payloads appear when injecting into the username. In large applications, you'll likely miss some, potentially leaving vulnerabilities undetected.

This is where FlowMate comes into play, our novel tool to detect data flows in applications for enhanced vulnerability assessments. FlowMate consists of two components: A BurpSuite plugin and a data flow graph based on Neo4j. It records inputs to the application as you go through the pages. In contrast to existing tools that require server-side access, FlowMate works from a black-box perspective by observing HTTP request and response pairs. Thereby FlowMate records all input parameters and locations as well as user-supplied values. In parallel, all HTTP responses from the server are matched against the central store of already identified parameter values to find occurrences of known input parameters. This results in a data graph, mapping inputs to outputs simply while using the application.

Understanding the data flow results in a significant improvement of test coverage in web app pentests, as all input and output occurrences of parameters can be systematically tested for vulnerabilities. More precisely, analysts can use FlowMate in the following ways: First, for a given input parameter, FlowMate shows all output locations, thus enabling verification of output filtering and encoding, even across role, tenant, and session boundaries. Second, for a given form, FlowMate visualizes all parameters and their respective output locations across the application.

## Code
https://github.com/usdAG/FlowMate

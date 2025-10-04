# AegiScan: A Static Dataflow Analysis Framework for iOS Applications

## Description
iOS is one of the most popular mobile operating systems worldwide, making the security of its applications a public concern. However, there's still a lack of powerful and efficient static dataflow analysis tools for iOS applications, which is essential for vulnerability scanning.

Conducting static dataflow analysis on iOS app binaries presents the following challenges:

1. Objective-C's runtime features, e.g., dynamically dispatched functions (objc_msgsend), pose an obstacle in static method resolution.

2. Classes, structs, and inter-module operations are complicated in context-sensitive and inter-procedural dataflow analysis.

3. Optimization techniques, e.g., app thinning and symbol stripping, increase the complexity of analysis.

To this end, we propose AegiScan, a static dataflow analysis framework for iOS application binaries. It utilizes top-down type propagation to resolve Objective-C MsgSend calls, thereby reconstructing the call graph. It then generates the Code Property Graph for each function to establish context-sensitive dataflow and combines them based on the call graph to facilitate inter-procedural analysis. Moreover, AegiScan parses runtime data segments to recover information lost during optimization, incorporating it into the analysis.

AegiScan is featured with a combination of static analysis and graph database, which makes tasks like vulnerability scanning efficient since the binary analysis only needs to be conducted once, with the results stored in the database for multiple queries. In our experiment, the analysis on a 130MB iOS App binary can be completed in less than 20 minutes. In addition, we develop query APIs based on graph database query language to facilitate vulnerability scanning.

To demonstrate the capability of AegiScan, we applied it to popular iOS Apps and critical macOS system services. It discovered various vulnerabilities, including 0-days in Apple native system services leading to local privilege escalation. This talk will also shed light on some interesting and thought-provoking vulnerabilities.

## Code
https://github.com/alibaba/AegiScan

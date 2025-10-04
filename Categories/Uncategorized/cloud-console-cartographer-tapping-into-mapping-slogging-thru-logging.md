# Cloud Console Cartographer: Tapping Into Mapping > Slogging Thru Logging

## Description
Event logs are a fundamental resource for security professionals seeking to understand the activity occurring in an environment. Cloud logs serve a similar purpose as their on-premise counterparts, though differing significantly in format and granularity between cloud providers. While most cloud CLI tools provide a one-to-one correlation between an API being invoked and a single corresponding API event being generated in cloud log telemetry, browser-based interactive console sessions differ profoundly across cloud providers in ways that obfuscate the original actions taken by the user.

For example, an interactive AWS console session produces 300+ CloudTrail events when a user clicks IAM->Users. These events are generated to support the numerous tiles and tables in the AWS console related to the user's clicked action but are never explicitly specified by the user (e.g. details concerning potential user groups, MFA devices, login profiles or access keys and their usage history for each IAM user in the paginated results). This backend behavior presents significant challenges for security analysts and tooling seeking to differentiate API calls explicitly invoked by a user from secondary API invocations merely supporting the AWS console UI.

Since March 2023 the presenters have developed a solution to this challenge and are proud to demo and release the open-source Cloud Console Cartographer framework (including a full CLI and supplemental GUI visualizer) as part of this presentation.

The presenters will demonstrate the extent of the console logging problem and the technical challenges and capabilities required to solve it, showcasing the tool's usefulness in translating real-world examples of malicious console sessions produced by notable cloud threat actors during first-hand incident response investigations.

Come and learn how the open-source Cloud Console Cartographer framework can provide clarity for threat hunters and detection engineers alike, helping defenders stop slogging through logging while putting the "soul" back in "console."

## Code
https://github.com/Permiso-io-tools/CloudConsoleCartographer

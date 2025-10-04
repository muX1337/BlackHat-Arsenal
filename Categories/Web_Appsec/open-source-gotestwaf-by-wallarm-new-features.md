# Open-Source GoTestWAF by Wallarm: New Features

## Description
GoTestWAF is a well-known open-source tool for evaluating Web Application Firewalls (WAFs), Runtime Application Self-Protection (RASPs), Web Application and API Protection (WAAP), and other security solutions by simulating attacks on the protected applications and APIs. The tool supports an extensive array of attack vectors, evasion techniques, data encoding formats, and runs tests across various protocols, including traditional web interfaces, RESTful APIs, WebSocket communications, gRPC, and GraphQL. Upon completion of the tests, it generates an in-depth report grading efficiency of solution and mapping it against OWASP guidelines.

The recently added features to the GoTestWAF are:

- Vendor Identification/Fingerprinting: With session handling improvements, GoTestWAF can automatically identify security tools/vendors and highlights findings in the report.

- OWASP Core Rule Set Testing: A script is added to generate test sets from the OWASP Core Rule Set regression testing suite. These vectors are not available by default and require additional steps as outlined in the readme.

- Regular Expressions for WAF Response Analysis: Regular expressions can be used to analyze WAF responses.

- Cookie Handling: GoTestWAF can consider cookies during scanning and update the session before each request. This allows scanning hosts that require specific WAF-specific cookies, as otherwise, requests are blocked.

- Email Report Sending: GoTestWAF interactively prompts for an email address to send the report.

- New Placeholders: Numerous new placeholders have been added, listed in the readme's "How It Works" section.

## Code
https://github.com/wallarm/gotestwaf

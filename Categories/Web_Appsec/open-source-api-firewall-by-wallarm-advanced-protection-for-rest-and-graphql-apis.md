# Open-Source API Firewall by Wallarm - Advanced Protection for REST and GraphQL APIs

## Description
The API Firewall ensures strict API request and response validation, adhering to both OpenAPI and GraphQL schemas. By employing a positive security model, it enhances API security by allowing only the traffic that meets a predetermined API specification for requests and responses, effectively blocking all other traffic. It's designed to work in cloud-native environments with a huge amount of traffic and is optimized for near-zero latency.

The key features of Wallarm's API Firewall are:

Endpoint Security: Secure REST and GraphQL API endpoints by blocking non-compliant requests/responses

Data Breach Prevention: Stop API data breaches by blocking malformed API responses

Shadow API Discovery: Discover Shadow API endpoints

Specification Adherence: Block attempts to use request/response parameters not specified in an OpenAPI specification

Token Validation:  Validate JWT access tokens and  other OAuth 2.0 tokens using introspection endpoints

Security Enhancements: Denylist compromised API tokens, keys, and cookies

Wide Range Attacks Protection: The API Firewall supports ModSecurity Rules and OWASP Core RuleSet v3/v4

Monitoring: Graphs and metrics of traffic processed by the API Firewall to provide full information about the protected API status and attacks attempts

The latest update of the API Firewall includes a new user interface that simplifies configuration, improves the control over the traffic processed by the API Firewall and sent to the protected API, and support for ModSecurity rules, enabling integration with the OWASP Common Rule Set (CRS) to enhance the protection capabilities against common web attacks. It also offers API rate limiting for specified endpoints to prevent API abuse, customizable response actions for each endpoint, and additional graphs and metrics to improve traffic monitoring and attack analysis.

This product is open-source and can be found on DockerHub, where it has impressively reached 1 billion downloads.

## Code
https://github.com/wallarm/api-firewall

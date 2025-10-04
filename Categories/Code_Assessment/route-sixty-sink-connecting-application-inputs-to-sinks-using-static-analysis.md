# Route Sixty-Sink: Connecting Application Inputs to Sinks Using Static Analysis

## Description
Route Sixty-Sink is an open source static analysis tool that traces the flow of user input through any .NET binary and determines whether it is passed as an argument to a dangerous function call (a "sink"). Route Sixty-Sink does this using two main modules:

1. RouteFinder, which enumerates API routes in MVC-based and classic ASP page web applications.
2. SinkFinder, which takes an entry point and creates a call graph of all classes and method calls. Then, it queries strings, method calls, and class names for "sinks".

By tying these two pieces of functionality together, Route Sixty-Sink is able to quickly identify high fidelity vulnerabilities that would be difficult to discover using black box or manual static analysis approaches.

We have used Route Sixty-Sink to reveal and successfully exploit vulnerabilities including unsafe object deserialization, SQL injection, command injection, arbitrary file uploads and access, authorization bypasses, and more in both open-source and proprietary .NET applications.

## Code
https://github.com/mandiant/route-sixty-sink

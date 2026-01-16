# Project Foxhound

## Description
The web has seen a paradigm shift in recent years, from on-premise, monolithic server applications, to collections of cloud-based microservices. As such, much of the application logic has shifted from the server to the client, with program logic running on a user's browser. This shift has brought with it a new class of client-side web vulnerabilities, the most prominent being client-side (or DOM-based) cross-site scripting (XSS). Most state-of-the-art tools, however, are still focused on detection of their server-side counterparts (such as reflected XSS). Hunting for client-side issues, remains a manual effort, requiring time-intensive and costly penetration tests.

Project Foxhound is an innovative open-source tool for the detection of security and privacy issues in client-side (JavaScript) code. So far, it has been used to detect security vulnerabilities such as XSS, CRSF, request hijacking, markup injection, open redirects and memory corruption in WebAssembly, to name a few! In addition, Foxhound can be used to detect privacy violations such as browser fingerprinting, behavioural biometrics and perform comparitive privacy analysis.

Foxhound works by detecting potentially dangerous data-flows in the browser, using a technique known as dynamic taint tracking. Unlike other tools, Foxhound records detailed information about data manipulations, allowing filtering of sanitized flows and therefore reducing false positives. Foxhound can be seamlessly integrated into existing browser automation frameworks such as Playwright or Selenium, or used interactively to assist penetration tests. Foxhound is based on the popular Firefox web browser, and as such has a high compatibility with a small performance overhead.

## Code
https://github.com/SAP/project-foxhound

# Monitoring and Detecting Leaks with GitAlerts

## Description
Most organisations put significant effort into maintaining their public GitHub repositories. They safeguard these repositories against various security vulnerabilities and routinely scan for sensitive information, ensuring thorough checks have been carried out before making anything public. However, an aspect that is often overlooked is the monitoring of the public activities of their organisation's users.

Developers within organisations frequently experiment and test ideas in a public setting, which may inadvertently include sensitive code, hardcoded credentials, secrets, internal URLs, and other proprietary information. This oversight can lead to significant security risks, making it crucial for organisations to monitor such activities to prevent potential data breaches.

Recent studies on data breaches reveal a startling trend. The leakage of secrets and sensitive information often occurs via individual repositories, rather than organisational ones. This fact underscores the importance of monitoring not just the organisation's repositories but also those created and maintained by individual users.

This talk aims to shed light on such cases related to GitHub. We will delve into real-world examples, discuss the common pitfalls, and suggest effective strategies to guard against these potential security risks.

## Code
https://github.com/boringtools/git-alerts

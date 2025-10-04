# SCodeScanner - An Open-Source Source-Code Scanner

## Description
SCodeScanner is a powerful tool for identifying vulnerabilities in source-code. It is designed to be easy to use and provides a range of features to help users quickly and accurately identify vulnerabilities with fewer false positives.

Some key features of SCodeScanner include:

- Support multiple languages: SCodeScanner is capable of scanning source code written in multiple languages such as JAVA, PHP and YAML. The most commonly used languages in web development.

- Relatively Less false positives: SCodeScanner includes flags that help to eliminate false positives and only report on vulnerabilities that are mostly confirmed to exist.

- Custom rules: SCodeScanner works with semgrep and allows users to create their own rules to scan for advanced patterns.

- Ability to track user input variables: SCodeScanner can identify instances where user input variables are defined in one file but used insecurely in another file for better coverage.

- Fast scanning: SCodeScanner's rules are designed to check for multiple vulnerabilities at once, which results in a faster scanning process.

- Integration: SCodeScanner can integrate with CI/CD pipelines and also pass results to bug-tracking services such as Jira and Slack, allowing users to easily share the results of their scans with their team.

- Scan mutltiple ways: It automatically download all git repo mentioned inside a txt file and start scan. Not only this but also support git, folder, file scans aswell.

Proof of results, SCodeScanner has already found 5 vulnerabilities in multiple Wordpress plugins and has been awarded following CVEs:

CVE-2022-1604
CVE-2022-1465
CVE-2022-1474
CVE-2022-1527
CVE-2022-1532

Overall, SCodeScanner is a valuable tool for any developer or security professional looking to identify vulnerabilities in their source-code before it is published in production. Its fast scanning, less false positives, and CI/CD pipeline integrations as well as bug-tracking services, make it a powerful tool for ensuring the security of your code.

## Code
https://github.com/agrawalsmart7/scodescanner

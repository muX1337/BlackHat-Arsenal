# FACT 4.0

## Description
Analyzing Firmware specifically to identify potential vulnerabilities is a common activity for security analysts, pentesters, researchers or engineers concerned with embedded devices such as in IoT. FACT offers an automated and usable platform to gain an immediate overview of potential vulnerabilities based on the firmware of a device and supercharges the process of finding deep vulnerabilities.

For this FACT automatically breaks down a firmware into its components, analyzes all components and summarizes the results. The analysis can then be perused in the desired amount of detail using either the responsive web application or a REST API.

The offered analyses include a list of included software and libraries, a matching of said software to CVE databases, identification of hard-coded credentials, private key material and weak configuration among others. FACT also applies source and binary code analysis to identify (possibly exploitable) bugs in the components and offers a large amount of meta data for further manual analysis.

A focus of recent development has been to offer more information regarding interdependencies between firmware components to ease the identification of data flow inside a firmware. This allows quickly grading the risk involved with uncovered vulnerabilities or configuration flaws by finding possible attack vectors concerning given component.

Finally, FACT offers multiple ways to collect and fuse analysis results, such as firmware comparison, advanced search options including regular expression on binary components and an integrated statistics module.

## Code
https://github.com/fkie-cad/FACT_core

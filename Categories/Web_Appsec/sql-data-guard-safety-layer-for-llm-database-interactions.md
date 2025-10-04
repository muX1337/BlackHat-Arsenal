# sql-data-guard: Safety Layer for LLM Database Interactions

## Description
SQL is the go-to language for performing queries on databases and for a good reason - it's well known, easy to use and pretty simple. However, it seems that it's as easy to use as it is to exploit and SQL injection is still one of the most targeted vulnerabilities especially nowadays with the proliferation of "natural language queries" harnessing LLM power to generate and run SQL queries.

To help solve this problem, we developed sql-data-guard, an open-source project designed to verify that SQL queries access only the data they are allowed to. It takes a query and a restriction configuration, and returns whether the query is allowed to run or not. Additionally, it can modify the query to ensure it complies with the restrictions. sql-data-guard has also a built-in module for detection of malicious payloads, which it can report on and remove malicious expressions before query execution.

sql-data-guard is particularly useful when constructing SQL queries with Large Language Models (LLMs), as such queries can't run as prepared statements. Prepared statements secure a query's structure, but LLM-generated queries are dynamic and lack this fixed form, increasing SQL injection risk. sql-data-guard mitigates this by inspecting and validating the query content.

By verifying and modifying queries before they are executed, sql-data-guard helps prevent unauthorized data access and accidental data exposure. Adding sql-data-guard to your application can prevent or minimize data breaches and sql-injection attacks impact, ensuring that only permitted data is accessed.

Connecting LLMs to SQL databases without strict controls can risk accidental data exposure, as models may generate SQL queries that access sensitive information. OWASP highlights cases of poor sandboxing leading to unauthorized disclosures, emphasizing the need for clear access controls and prompt validation. Businesses should adopt rigorous access restrictions, regular audits, and robust API security, especially to comply with privacy laws and regulations like GDPR and CCPA, which penalize unauthorized data exposure.

## Code
https://github.com/ThalesGroup/sql-data-guard

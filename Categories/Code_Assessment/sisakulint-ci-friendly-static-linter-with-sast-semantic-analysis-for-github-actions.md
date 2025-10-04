# sisakulint - CI-Friendly static linter with SAST, semantic analysis for GitHub Actions

## Description
In recent years, attacks targeting the Web Application Platform have been increasing rapidly.

It is intended to be used mainly by software developers and security personnel at user companies who work in blue teams. It is easy to introduce because it can be installed from brew.

It also implements an autofix function for errors related to security features as a lint.

It supports the SARIF format, which is the output format for static analysis. This allows Review Dog to provide a rich UI for error triage on GitHub.

Main Tool features:

id collision detection

Environment variable names collision

docs : https://sisakulint.github.io/docs/idrule/

Hardcoded credentials detection  by rego query language

docs : https://sisakulint.github.io/docs/credentialsrule/

commit-sha rule

docs : https://sisakulint.github.io/docs/commitsharule/

premissions rule

docs : https://sisakulint.github.io/docs/permissions/

workflow call rule

docs : https://sisakulint.github.io/docs/workflowcall/

timeout-minutes-rule

docs : https://sisakulint.github.io/docs/timeoutminutesrule/

## Code
https://github.com/reviewdog/reviewdog?tab=readme-ov-file#sarif-format

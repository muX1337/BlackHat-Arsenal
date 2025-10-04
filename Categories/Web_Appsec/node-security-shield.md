# Node Security Shield

## Description
Node Security Shield (NSS) is a Developer and Security Engineer friendly module for Securing NodeJS Applications by allowing developers to declare what resources an application can access.

NSS is an Open source Runtime Application Self-Protection (RASP) tool and aims at bridging the gap for comprehensive NodeJS security.

Inspired by the log4J vulnerability ([[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) which can be exploited because an application can make arbitrary network calls, we felt there is a need for an application to have a mechanism so that it can declare what privileges it allows to make the exploitation of such vulnerabilities harder by implementing additional controls.

To achieve this, NSS (Node Security Shield) has a Resource Access Policy and the concept is similar to CSP (Content Security Policy). Resource Access Policy lets developer/security engineers declare what resources an application should access and Node Security Shield will enforce it.

If an Application is compromised and requests 'attacker.com' which violates Resource Access Policy. Node Security Shield will block it automatically and thus protect the application from malicious attacks.

## Code
https://github.com/DomdogSec/NodeSecurityShield

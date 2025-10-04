# Node Security Shield - A Lightweight RASP for NodeJS Applications

## Description
Node Security Shield (NSS) is an Open source Runtime Application Self-Protection (RASP) tool which aims at bridging the gap for comprehensive NodeJS security.
NSS is designed to be Developer and Security Engineer friendly and enables them to declare what resources an application can access.
Inspired by the Log4Shell vulnerability which can be exploited because an application can make arbitrary network calls, we felt there is a need for an application to have a mechanism so that it can declare what privileges it allows in order to make the exploitation of such vulnerabilities harder by implementing additional controls.
In order to achieve this, NSS (Node Security Shield) has a Resource Access Policy and the concept is similar to CSP (Content Security Policy). Resource Access Policy lets developer/security engineers declare what resources an application should access and Node Security Shield will enforce it.
If the Application is compromised and requests 'attacker.com' Node Security Shield will block it automatically and thus protect the application from malicious attacks.
Node Security Shield was first announced in Black Hat Asia 2022 Arsenal. This is the first major update after its release. This release adds support for the 'module-level' Resource Access Policy.
Allowing Developers or Security Engineers to declare what resources a module can access.

## Code
https://github.com/DomdogSec/NodeSecurityShield

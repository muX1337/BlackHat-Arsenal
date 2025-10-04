# Makes: A tool for avoiding supply chain attacks

## Description
As the open-source ecosystem keeps growing, and applications increase their reliance on public libraries, we also see a spike in supply chain attacks. Recent scandals like SolarWinds or Log4j remind us how exposed software is when it comes to malicious, vulnerable or broken packages. Modern applications have thousands of dependencies, which means that managing dependency trees only becomes harder over time, while exposure keeps rising.

Think about how often you need things like

- keeping execution environments frozen for a strict dependency control (I'm looking at you, supply chain attacks);
- running applications locally so you can try whatever you are coding;
- executing CI/CD pipelines locally so you can make sure jobs (Linters, tests, deployments, etc.) are passing;
- running applications anywhere, no matter what OS you are using;
- knowing the exact dependency tree your application has for properly managing risk (Software Bill of Materials);
- making sure applications will work as expected in production environments.

At Fluid Attacks, we have experienced such concerns firsthand. That is why we created Makes, an open-source framework for building CI/CD pipelines and application environments in a way that is

- secure: Direct and indirect dependencies for both applications and CI/CD pipelines are cryptographically signed, granting an immutable software supply chain;
- easy: Can be installed with just one command and has dozens of generic CI/CD builtins;
- fast: Supports a distributed and completely granular cache;
- portable: Runs on Docker, VM's, and any Linux-based OS;
- extensible: Can be extended to work with any technology.

Makes is production ready and used currently in 11 different products that range from static and dynamic websites to vulnerability scanners. It was released on GitHub in July 2021 and has already been starred 170 times. It currently has 9 contributors from the community and gets a minor update each month.

## Code
https://github.com/fluidattacks/makes

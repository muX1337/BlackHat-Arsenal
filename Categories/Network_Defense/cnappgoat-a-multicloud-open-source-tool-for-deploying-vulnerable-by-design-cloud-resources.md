# CNAPPgoat: A Multicloud Open-Source Tool for Deploying Vulnerable-by-Design Cloud Resources

## Description
CNAPPgoat is a CLI tool designed to deploy vulnerable-by-design cloud infrastructure.

The tool is designed to modularly provision intentionally vulnerable components in cloud environments with simple commands: launch a container with a crypto-miner installed, spawn a machine with a vulnerable image, create a public IAM role, and many more scenarios.

These capabilities empower defenders to test their protective strategies, tools, and procedures, and for offensive professionals to refine their skills and tooling. Instead of trusting their systems and procedures to prevent risk, they can manufacture risk in a controlled environment to verify that they actually do.

CNAPPgoat supports modular deployment of various vulnerable scenarios and is a multi-cloud tool. CNAPPgoat is built on Pulumi and supports multiple programming languages. It operates as a CLI tool, requiring no specific IaC expertise, enabling a wide range of professionals to deploy and monitor environments.

CNAPPgoat helps:
* Security professionals create sandboxes to test their teams, procedures, and protocols
* Pentesters use it to provision a "shooting range" to test their skills at exploiting the scenarios and developing relevant capabilities
* Security teams benchmark CNAPP solutions against known environments to prove their ability to deliver what they promise
* Instructors create vulnerable environments for hands-on workshops or chalk talks
* Educators create learning environments where cloud infrastructure risks can be explored, understood - and avoided

## Code
https://github.com/ermetic-research/cnappgoat

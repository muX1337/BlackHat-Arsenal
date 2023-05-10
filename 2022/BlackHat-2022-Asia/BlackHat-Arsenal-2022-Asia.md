# BlackHat Arsenal 2022 Asia

Links to the repositories or other stuff of the BlackHat Asia 2022

<details>
  <summary>Pwnppeteer - Phishing Post {Exploi/Automa}tion at Scale</summary>
  
Phishing is well know attack but more and more company have implemented countermeasure to limit the efficiency of this kind of attack. For example, Multi-Factor Authentication (MFA) is being adopted to make password spraying and standard phishing ineffective. Countermeasures adopted raise the exploitation bar, for attacker.

But what happens if you can easily tamper MFA too? If you can proxy all traffic, directly steal sessions and automate malicious actions before the credentials are changed or the attack detected? What do you think if you phish an SSO portal and then you're able to instrument all applications granted with a SSO token...

The goal is to share my experience of a massive phishing campaign, how you can use Muraena/Necrobrowser at scale and show how we can phish and get a temporary access to steal enough data or add some persistents access in order to come back later. And of course before being detected and losing access.

https://github.com/muraenateam/pwnppeteer
</details>

<details>
  <summary>Tsurugi Linux Project: The Right Tool in the Wrong Time</summary>
  
  Any DFIR analyst knows that everyday in many companies, it doesn't matter the size, it's not easy to perform forensics investigations often due to lack of internal information (like mastery all IT architecture, have the logs or the right one...) and ready to use DFIR tools.

As DFIR professionals we have faced these problems many times and so we decided last year to create something that can help who will need the right tool in the "wrong time" (during a security incident).

And the answer is the Tsurugi Linux project that, of course, can be used also for educational purposes.
After more than a year since the last release, a Tsurugi Linux special BLACK HAT EDITION with this major release will be shared with the participants before the public release.

https://tsurugi-linux.org/index.php
</details>

<details>
  <summary>The Dependency Combobulator</summary>
  
The Dependency Combobulator is a modular and extensible framework to detect and prevent dependency confusion leakage and potential attacks. This facilitates a holistic approach for ensure secure application releases that can be evaluated against different sources (e.g., GitHub, Artifactory) and many package management schemes (e.g., ndm, pip, maven).

The framework can be used by security auditors, pentesters and even baked into an enterprise's application security program and release cycle in an automated fashion.

This major new release will include support for a new line of package schemes / artifact ingestion.

https://github.com/apiiro/combobulator
</details>

<details>
  <summary>Telegrip Forensic Tool</summary>

The use of social media applications is growing rapidly worldwide which is driven by the growth of usage of mobile devices since it has changed the way we live our lives significantly. However, these applications are being used by criminals with bad intentions to help them in their interactions and communication in order to conduct cybercrimes. Which makes a significant need for forensics tools that provide features in which the digital evidence can be preserved and presented in a clear and factual manner. Telegrip, a Python-based forensic tool aims to acquire and analyze sparse images, preserve evidence related to Telegram application while maintaining the integrity of the evidence gathered and reports produced. Telegrip provides several features that overcome the limitations in the existing tools and assist digital investigators to extract and analyze artifacts generated on Android mobile phones by Telegram easily by using an interactive graphical user interface (GUI).
  
https://github.com/Telegrip/Telegrip
</details>

<details>
  <summary>Rate Unlimiter</summary>
  
Rate limiters are mechanisms placed on endpoints to control the rate of traffic that is received or sent; for instance, blocking any subsequent requests for 10 minutes from an IP address when its traffic rate exceeds the threshold limit of 10 hits per minute on a given endpoint. The example given is a static rate limit policy. My team hypotheses that in time to come, there will be a popularisation of dynamic rate limiters (new breed / advanced version of static rate limiters) wherein threshold values of requests or hits, time buckets, and blocking penalty periods are dynamically and automatically adjusted according to the nature of traffic and/or relevant detection algorithms.

With such an outlook, our team has developed a pre-emptive offensive tool, the "Rate Unlimiter", which will, on-the-fly, reverse-derive the underlying rate policies for both static and dynamic rate limiters, allowing security researchers to maximise their gains against a target endpoint with their pool of IP addresses. For instance, when used against a /login endpoint, it will test and intelligently determine the underlying and even overlapping rate limit policies, for instance, "10hits/min->block for 15mins" for policy 1 and "25hits/3mins->block for 45mins" for policy 2. And should that rate limit policy be a dynamic one, the Rate Unlimiter will derive the latest values automatically to maximise the total number of successful requests to the given endpoint over a stipulated period of time and available resources.

Info:No links
</details>

<details>
  <summary>Kubesploit: A Post-Exploitation Framework, Focused on Containerized Environments</summary>
  
Kubesploit is a post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments, and built on top of Merlin project by Russel Van Tuyl (@Ne0nd0g).
It supports Go modules and has container breakout modules, kubelet attack, and scanning modules.

https://github.com/cyberark/kubesploit
</details>

<details>
  <summary>ChainAlert: Alert Developers and Open Source Maintainers of Potential Supply Chain Attacks and Suspicious Package Release</summary>
  
Recent NPM package takeovers such as "coa" and "UAParser.js" have affected organizations by the thousands. This has amplified the need for a monitoring system to alert developers, Open Source maintainers, and the community in case of suspicious activities that might hint of an account takeover or malicious package being published.

Learning the lessons from these attacks, we have created ChainAlert, which continuously monitors new open source releases and helps minimize the damages from future attacks. ChainAlert does this by closing the time gap between takeover events to detection and mitigation. This is especially important for packages that aren't very actively maintained and there aren't many people who would notice a problem until it is too late.

In many cases, even unmaintained packages have millions of weekly downloads, making a takeover spread very fast, amplifying the risk to the community.

In this session, you will learn about:

- Recent history of NPM account takeovers and lessons learned.
- What really happens in the wild-wild-west of NPM uploads.
- Common developer bad practice that might lead to flag a release as suspicious.
- How to protect yourself and your organization with ChainAlert against possible supply chain attacks.
- How to contribute back to the community by detecting more suspicious activity.

https://github.com/Checkmarx/chainalert-github-action
</details>

<details>
  <summary>CrowdSec: The Open-Source and Participative IPS</summary>
  
Discover CrowdSec, an open-source and participative IPS, relying on both IP behavior analysis and IP reputation. CrowdSec analyzes visitor behavior & provides an adapted response to all kinds of attacks. The solution also enables users to protect each other. Each time an IP is blocked, all community members are informed so they can also block it. Already used in 120+ countries across 6 continents, the solution builds a real-time IP reputation database that will benefit individuals, companies, institutions etc.  

https://github.com/crowdsecurity/crowdsec
</details>

<details>
  <summary>BloodHound</summary>

BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.

https://github.com/BloodHoundAD/BloodHound
</details>

<details>
  <summary>C0deVari4nt</summary>
  
C0deVari4nt is a variant analysis and visualisation tool that inspects codebases for similar vulnerabilities. It leverages CodeQL, a semantic code analysis engine, to query code based on user-controlled CodeQL query templates and passes the results to Neo4j for further exploration and visualisation. This enables quick and comprehensive variant analysis based on previous vulnerability reports. The Neo4j visualisation feature provides additional insight for developers into vulnerable code paths and allows them to effectively triage potential variants.

The Log4Shell incident in December 2021 highlighted the difficulties open-source developers face in responding to vulnerability reports. After the initial patch for CVE-2021-44228, which allowed unauthenticated remote attackers to take control of devices running vulnerable versions of Log4j 2, Apache released 3 additional patches to address related vulnerabilities and unmitigated edge cases.

Open-source developers often lack training in comprehensive code review and face problems in identifying variants of a vulnerability, leading to incomplete patches. Although CodeQL query suites exist to facilitate quick analysis of the codebase, the results returned from these suites may result in significant false positive rates. Furthermore, these suites rely on predefined queries which do not support variant analysis and are not customised for individual codebases. As such, open-source projects often respond to vulnerability reports in a piecemeal manner that misses potential variants.

C0deVari4nt provides a platform for developers to easily conduct variant analysis without the significant overhead of writing their own CodeQL queries. This gives developers the flexibility to customise CodeQL templates by providing codebase-specific information such as a particular source and sink of a vulnerability. The results will be visualised in a simplified Neo4j graph for developers to quickly identify potential variants. As such, developers will be able to effectively address entire classes of bugs from a single vulnerability report.  

https://github.com/whitesquirrell/C0deVari4nt
</details>

<details>
  <summary>TMoC: Threat Modeler on Chain</summary>
  
TMoC(Threat Modelers on Chain) is the blockchain-based threat modeling tool that can perform threat modeling using the collective intelligence of security experts. It provides better quality of threat modeling results to threat modeling players and those customer. And TMoC provide massive collaborative environment to threat modeling players via blockchain technology. Also, existing threat modeling automation tools enable rapid threat modeling according to DevOps, but TMoC is the first tool that utilizes collective intelligence.

Player of TMoC consists of customer, performer, evaluator, and arbiter. Customers who want to perform threat modeling by utilizing the collective intelligence of experts can start threat modeling by uploading a DFD(Data Flow Diagram). When someone uploads a DFD, experts can join the TMoC platform as performers or evaluators. A community of experts who participated as performers should perform the threat modeling process on the uploaded DFD. Performers can get a certain amount of tokens as incentives by adding new or critical items to the threat modeling process. However, all threat modeling processes are evaluated through evaluator. As a result of the evaluation, if inappropriate items are uploaded or duplicate items exist, the performer cannot obtain incentives. Evaluators can get a certain amount of tokens as incentives through such evaluation activities. In addition, to prevent the evaluator from conducting malicious or inappropriate evaluations, several arbiters are configured that act as watchers through the votes of the evaluators.

This reward model fosters a competitive environment that motivates experts to analyze better threat modeling results. This allows the threat modeling results to become more detailed as the number of TMoC participants increases, which can lead to better results.

Finally, TMoC is uploaded to github in the form of open source. In this presentation, we would like to tell you more about the developed tool and show you a demo.

https://github.com/SANELab/TMOC_Demo

</details>

<details>
  <summary>ReconPal: Leveraging NLP for Infosec</summary>
  
Recon is one of the most important phases that seem easy but takes a lot of effort and skill to do right. One needs to know about the right tools, correct queries/syntax, run those queries, correlate the information, and sanitize the output. All of this might be easy for a seasoned infosec/recon professional to do but for rest, it is still near to magic. How cool it will be to ask a simple question like "Find me an open Memcached server in Singapore with UDP support?" or "How many IP cameras in Singapore are using default credentials?" in WhatsApp chat or a web portal and get the answer?

The integration of GPT-3, deep learning-based language models to produce human-like text, with well-known recon tools like Shodan is the foundation of ReconPal. In this talk, we will be introducing ReconPal with audio support as well as report generation capabilities. We are also introducing a miniature attack module, allowing users to execute popular exploits against the server with just the voice commands. The code will be open-source and made available after the talk.

ROOTCON 14(2020): https://www.youtube.com/watch?v=C9w6-jlGyDE

Links will be available after the talk
</details>

<details>
  <summary>Node Security Shield</summary>
  
Node Security Shield (NSS) is a Developer and Security Engineer friendly module for Securing NodeJS Applications by allowing developers to declare what resources an application can access.

NSS is an Open source Runtime Application Self-Protection (RASP) tool and aims at bridging the gap for comprehensive NodeJS security.

Inspired by the log4J vulnerability ([[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) which can be exploited because an application can make arbitrary network calls, we felt there is a need for an application to have a mechanism so that it can declare what privileges it allows to make the exploitation of such vulnerabilities harder by implementing additional controls.

To achieve this, NSS (Node Security Shield) has a Resource Access Policy and the concept is similar to CSP (Content Security Policy). Resource Access Policy lets developer/security engineers declare what resources an application should access and Node Security Shield will enforce it.

If an Application is compromised and requests 'attacker.com' which violates Resource Access Policy. Node Security Shield will block it automatically and thus protect the application from malicious attacks.

https://github.com/DomdogSec/NodeSecurityShield
</details>

<details>
  <summary>kdigger: A Context Discovery Tool for Kubernetes Penetration Testing</summary>
  
kdigger, short for "Kubernetes digger", is a context discovery tool for Kubernetes penetration testing. This tool is a compilation of various plugins called buckets to facilitate pentesting Kubernetes from inside a pod.

The idea behind this tool is to quickly gather various information about your Kubernetes containerized environment, like a checklist, to give you, as a pentester, hints about the actual situation. For example, kdigger can help you:
- notice that you are running inside a privileged container;
- notice that you are running inside a container sharing the PID namespace with other container in its pod;
- verify if you have a Kubernetes API token at your disposition that has interesting capabilities;
- scan the admission control, if you have the right to create pods, in order to create a more privileged pod and escalate;
- retrieve all the available services running inside of the cluster you are in;
- scan the allowed system calls in the container.

https://github.com/quarkslab/kdigger
</details>

<details>
  <summary>ThunderCloud: Attack Cloud Without Keys!</summary>
  
ThunderCloud

"You can't audit a cloud environment without access keys!!".

Well. That's not completely true.

There is a good number of tools that help security teams find cloud misconfiguration issues. They work inside-out way where you give read-only access tokens to the tool and the tool gives you misconfigurations.

There's no single tool that helps Red Teamers and Bug Hunters find cloud misconfiguration issues the outside-in way.

This outside-in approach can find issues like:

1. S3 directory listing due to misconfigured Cloudfront settings
2. Amazon Cognito misconfiguration to generate AWS temporary credentials
3. Public snapshots
4. Generate Account takeover Phishing links for AWS SSO
5. Leaked Keys permission enumeration
6. IAM role privilege escalation
a) From leaked keys
b) Lambda Function

This exploitation framework also helps teams within organizations to do red teaming activities or run it across the accounts to learn more about misconfigurations from AWS and how badly they can be exploited.

https://github.com/rnalter/thundercloud
</details>

<details>
  <summary>Lupo: Malware IOC Extractor</summary>

Debugging module for Malware Analysis Automation.

I wrote Lupo mainly to automate and accelerate the process as much as possible. Lupo is a dynamic analysis tool that can be used as a module with the debugger (WinDBG).

The way the tool works is pretty straightforward. You load Lupo into the debugger and then execute it. It runs through the malware and collects predefined IOC and writes them to a text file on the disk. You can then use this information to contain and neutralize malware campaigns or simply respond to the security incident that you are working on.

https://github.com/malienist/lupo
</details>

<details>
  <summary>AISY: A Framework for Deep Learning-Based Side-Channel Analysis</summary>
  
Profiling side-channel attacks (SCA) allow evaluators to verify the worst-case security scenario of their products. Nowadays, deep learning has become the state-of-the-art method for profiling SCA as deep neural networks show the ability to learn side-channel leakages from protected implementations. While deep learning is a powerful technique for security evaluations, it offers numerous possibilities for neural network configurations and optimization techniques. Selecting the best setup for each evaluated product is far from trivial and requires expertise in SCA and deep learning fields. To improve SCA methods, and at the same time to be able to investigate the resistance of the product to more complex attack scenarios, researchers continuously propose new techniques.
Unfortunately, several obstacles are making the acceptance of such techniques a challenge. Security evaluators from the industry face difficulties following up on new promising methods. What is more, certification bodies also must be aware of new SCA techniques to issue the certifications. Indeed, one of the main issues is the lack of publicly available, easy-to-use frameworks that allow powerful and reliable side-channel analysis. Moreover, due to the absence of the uniformed evaluation/implementation method, the reproducibility of the outcomes is not easy to ensure.

We propose AISY as a tool to allow state-of-the-art deep learning-based SCA. AISY is a python-based open-source framework, and it provides state-of-the-art functionalities for profiling SCA with easy usage, extensibility, reproducibility, integrated database, and user interface. We envision a system where the user can efficiently run the attacks with few lines of code and based on state-of-the-art but also extend those functionalities to support new developments. AISY supports the complete development cycle for deep learning-based SCA: from dataset preparation to the automated development of new models and their assessment concerning the side-channel metrics.

https://github.com/AISyLab/AISY_Framework
</details>

<details>
  <summary>Nightingale: Docker for Pentesters</summary>
  
Docker containerization is the most powerful technology in the current market so I came with the idea to develop Docker images for Pentesters.

Nightingale contains all the required famous tools that will be required to the pentester at the time of Penetration Testing. This docker image has the base support of Debian and it is completely platform Independent.

You can either create a docker image in your local host machine or you can directly pull the docker images from the docker hub itself.

https://github.com/RAJANAGORI/Nightingale
</details>

<details>
  <summary>Mitigating Open Source Software Supply Chain Attacks</summary>

Software package managers have become a vital part of the modern software development process. They allow developers to easily adopt third-party software and streamline the development process. However, bad actors today reportedly leverage highly sophisticated techniques such as typo-squattng and social engineering to "supply" purposefully harmful code (malware) and carry out software supply chain attacks. For example, eslint-scope, a NPM package with millions of weekly downloads, was compromised to steal credentials from developers.

We have built a large-scale vetting infrastructure that analyzes millions of published NPM, Python, RubyGems software packages for "risky" code/attributes, and provides actionable insights into their security posture. Our system employs static code analysis as well as metadata analysis for detection. For example, inspired by the permissions model of Android/iOS, our system derives permissions needs by a package (e.g, file I/O, network I/O, process exec). Similarly, our metadata analysis module checks for package impersonation to detect typo-squatting attacks.

In this presentation, we will cover the technical details of our system and introduce a free command line (CLI) tool as well as a CI/CD plugin for developers to detect accidental installation of "risky" packages and mitigate software supply chain attacks. We have already detected a number of abandoned, typo-squatting, and malicious packages. We will present our findings, highlight different types of attacks and measures that developers can take to thwart such attacks. With our work, we hope to enhance productivity of the developer community by exposing undesired behavior in untrusted third-party code, maintaining developer trust and reputation, and enforcing security of package managers.

Company Github: https://github.com/ossillate-inc

Standalone CLI: https://github.com/ossillate-inc/packj
</details>

<details>
  <summary>In0ri: Open Source Defacement Detection With Deep Learning</summary>
  
In0ri is the first open source system for detecting defacement attacks by utilizing image-classification convolutional neural network. In this presentation, we will be demonstrating the process of setting up In0ri and have it detect defacement attacks. And optionally the process of training the machine learning model. We will also be explaining the reason behind In0ri's high accuracy when classifying defacement attacks.

https://github.com/J4FSec/In0ri
</details>

<details>
  <summary>Flopz: Patch, Debug and Instrument Firmware When All You Have Is a Binary</summary>
  
Embedded systems can be challenging to analyze. Especially on automotive systems, many things that we take for granted in other scenarios such as debugging and tracing can not always work. On some systems, hardware debugging resources are locked or used for something else, and sometimes they don't even exist at all!

Assuming that code can be dumped, the solution for this can be emulation, however emulating a rich embedded system can be painful and many times, only few aspects of the system can be sufficiently modeled. For some systems, it can be challenging to determine the environmental factors that influence whether the device behaves correctly or not.
What if there was an in-between? How can we debug, fuzz, and tamper embedded firmware without access to hardware debugging or emulation?

This is why we've created Flopz. Using Flopz, you can easily cut, patch, and instrument firmware in order to reverse engineer and attack all kinds of embedded devices. Flopz is a new, open-source, pythonic assembler toolkit for instrumenting firmware binaries and generating modular shellcode.

The tool does not require source code access and it does not require a working compiler toolchain either.

Combined with Ghidra, we show a simple but smart binary instrumentation method and a pythonic assembler to automatically patch large firmware binaries, enhancing them with interactive backdoors, as well as function- or basic-block trace capabilities. Showcasing a demo on a real-world device, we demonstrate how Flopz works and how it supports many popular embedded architectures such as RISC-V, ARM Thumb Mode and PowerPC VLE.

https://github.com/Flopz-Project/flopz
</details>

<details>
  <summary>Patronus: Swiss Army Knife SAST Toolkit</summary>
  
Patronus is a fully dockerised and comprehensive config driven Security Framework which helps to detect security vulnerabilities in the Software Development Life Cycle of any application. The framework inculcates a highly automated approach for vulnerability identification and management. With Patronus's fully whitebox approach, the framework currently covers four major verticals; Secrets Scanning, Software Composition Analysis, Static Application Security Testing and Asset Inventory. Finding all these four verticals together is a very strenuous task in the industry as no other framework currently solves this like Patronus which provides a fully comprehensive dashboard containing all the four verticals in a single central platform, and this is something very unique to Patronus. Patronus automatically identifies the latest code commits and focuses on the major aspects of the application source code to identify and detect key and high severity vulnerabilities within the application and aims for minimal false positives in the reports.

The framework focuses on the needs of the security engineers and the developers alike with a dedicated web dashboard to abstract all the nitty gritty technicalities of the security vulnerabilities detected and also empowers the user with higher level of vulnerability tracking for better patch management. The dashboard is built completely with analytics, functionality and maintaining ease in mind to demonstrate and display various metrics for the scans and vulnerabilities. It also helps to search, analyse and resolve vulnerabilities on-the-go and provides a completely consolidated vulnerability report.

Patronus is very powerful and hugely reduces the time and efforts of the security team in thoroughly reviewing any application from a security lens. The framework comes with an on-demand scanning feature apart from the scheduled daily automated scans, using which developers and security engineers can scan particular branches and repositories at any point of time in the SDLC, directly from the dashboard or integrations like Slack. The framework is completely adaptable and various softwares like Slack and Jira can be easily integrated directly with Patronus for better accessibility and tracking since most organisations today use these extensively.

https://github.com/th3-j0k3r/Patronus
</details>

<details>
  <summary>NtHiM (Now, the Host is Mine!): Super Fast Sub-Domain Takeover Detection</summary>

NtHiM, which stands for "Now, the Host is Mine!" is a Rust-based systems project, which enables security enthusiasts to discover subdomain takeover vulnerabilities in hostnames (domains and subdomains) from different organizations.

In this session, I will be discussing about the following things, apart from an introduction of myself as the project maintainer and your presenter for this session.

    Project Overview
        Brief Introduction (what this project actually is)
        Initiation Story (how I decided to start working on this project)
        Brief Logic Explanation (understanding the project workflow with a simple pseudocode)
        Project Features (getting to know about all of the things built into the project)
    User-level Video Documentation (Demonstration; including guides for the end-users of this project)
    Developer-level Video Documentation (Demonstration; including guides on how you can get started with extending or contributing to this project)
	
https://github.com/TheBinitGhimire/NtHiM
</details>

<details>
  <summary>KNX Bus Dump</summary>

KNX is a popular building automation protocol and is used to interconnect sensors, actuators and other components of a smart building together. Our KNX Bus Dump tool uses the Calimero java library, which we contributed to for the sake of this tool, to record the telegrams sent over a KNX bus. Particularly, our tool accesses the KNX bus through a TPUART connection but can be changed to use different connection mediums. The telegrams are dumped into a Wireshark-compatible hex dump file. Timestamps are provided and normalized to UTC time with nanosecond precision to perform data analysis and provide a timeline of the telegrams. The hex dump file can be imported into Wireshark, which can be configured to dissect the KNX telegrams with Wireshark's cEMI dissector.

Our tool can be used for protocol analysis of KNX sensors, actuators and other KNX devices. For example, we used the tool to understand our KNX devices and found irregular KNX telegrams. The tool is also ideal for security analysis of KNX devices given that it exposes all details of the involved protocol and data sent over the KNX bus.

Tcpdump and Wireshark cannot be used to dump telegrams sent over a KNX bus since we are dealing with native KNX telegrams, not TCP/IP packets. Wireshark and tcpdump can dump KNXnet/IP packets, which are TCP/IP packets. KNXnet/IP is a protocol for sending commands and data to a KNX bus over a TCP/IP network.

https://github.com/ChrisM09/KNX-Bus-Dump
</details>

<details>
  <summary>Ghostwriter</summary>
  
Ghostwriter is a part of your team. It enables collaborative management of penetration test and red team assessments. It helps you manage the critical pieces of every project, including client information, project plans, infrastructure, findings, and reports in one application.

Since its debut at Black Hat USA Arsenal in 2019, Ghostwriter has grown and matured. Last year was a building year for the project. Now, the development team is excited to re-introduce Ghostwriter with new features to be rolled out in Q1 and Q2 2022 – such as a new GraphQL API! This new version gives teams the power to manage their projects via the API layer and custom scripts or integration with third-party projects.

https://github.com/GhostManager/Ghostwriter
</details>

<details>
  <summary>Mobile App API Penetration Platform</summary>

There are many protections being applied to mobile applications nowadays, and most penetration testing engineer use primitive methods to crack them. Therefore, if we can modify the data or insert the payload of the vulnerability before the protection is processed, all the protections will be transparent to the penetration testers and there will be no concern about their implementation, making app API testing purer.

https://github.com/Daemonceltics/MAAPP
</details>

<details>
  <summary>Mobile Malware Mimicking Framework</summary>
  
Emulating malware is a great way to gain insight into the behaviour of threat actors, and to fetch the newest malware samples and modules from the source. Emulating Android malware using virtual machines is a resource intensive task that does not scale well. To resolve this, I wrote the open-source Mobile Malware Mimicking framework, or m3 in short. The framework is built to easily and scalable emulate Android malware whilst using very few resources. Currently, the renowned Anubis and Cerberus families are supported within the framework.

m3's architecture focuses on three main points: simplicity, security, and scalability. To simplify the implementation of new families, the framework is written in Java, which allows the usage of decompiled code snippets. Additionally, the framework provides internal APIs to simplify the workflow. Each bot contains a phone object, which contains many commonly used Android features in plain Java, optimised for emulation purposes. This way, decompiled code only needs minor tweaks before it is executable within the framework. The framework is secure, as unknown commands are logged and furthermore ignored. Due to its open-source nature, anyone can audit and improve the project. Due to the plain Java implementation of the bots, the framework requires very little memory, compared to the virtual machines that would otherwise be required. Adding more bots barely increases the memory usage, allowing a single machine to handle dozens of bots at once.

To use m3, one must first create one or more bots and provide all required details, after which the bots can be emulated. Logging of activities is done per bot, in both the standard output, and a log file per bot. This provides analysts with a detailed overview of the activities that occurred over time.

https://github.com/ThisIsLibra/m3
</details>

<details>
  <summary>SCYTHE: The Yara Signature Crafter that Fingerprints Honeypot Traffic</summary>
  
A fingerprinting engine that creates value from abusive traffic by generating attacker YARA signatures of various strictness levels to apply differing levels of mitigating friction. The tool further deploys honeypot entities to proactively perform threat actor attribution to identify and action against malicious actors rotating IP addresses.
</details>

<details>
  <summary>EMBA: Open-Source Firmware Security Testing</summary>
  IoT (Internet of Things) and OT (Operational Technology) are the current buzzwords for networked devices on which our modern society is based on. In this area, the used operating systems are summarized with the term firmware. The devices themselves, also called embedded devices, are essential in the private and industrial environments as well as in the so-called critical infrastructure.

Penetration testing of these systems is quite complex as we have to deal with different architectures, optimized operating systems, and special protocols. EMBA is an open-source firmware analyzer with the goal to simplify and optimize the complex task of firmware security analysis. EMBA supports the penetration tester with the automated detection of 1-day vulnerabilities on binary level. This goes far beyond the plain CVE detection: With EMBA you always know which public exploits are available for the target firmware. Besides the detection of already known vulnerabilities, EMBA also supports the tester on the next 0-day. For this, EMBA identifies critical binary functions, protection mechanisms and services with network behavior on a binary level. There are many other features built into EMBA, such as fully automated firmware extraction, finding file system vulnerabilities, hard-coded credentials, and more.

EMBA is the open-source firmware scanner, created by penetration testers for penetration testers.

https://github.com/e-m-b-a/emba
</details>

<details>
  <summary>Hayabusa</summary>

Hayabusa is a sigma-based threat hunting and fast forensics timeline generator for Windows event logs written in rust by Yamato Security. Rules can either be written sigma or built-in hayabusa rules that let the analyst extract out only the important fields for Windows DFIR investigations.

https://github.com/Yamato-Security/hayabusa
</details>




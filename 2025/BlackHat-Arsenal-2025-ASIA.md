<details>
  <summary>GitArmor: policy as code for your GitHub environment</summary>
  DevOps security does not only mean protecting the code, but also safeguarding the entire DevOps platform against supply chain attacks, integrity failures, pipelines injections, outsider permissions, worst practices, missing policies and more. 



DevOps platforms like GitHub can easily grow in repos, actions, tokens, users, organizations, issues, PRs, branches, runners, teams, wiki, making admins' life impossible. This means also lowering the security of such environment. 



GitArmor is a policy as code tool, that helps companies,teams and open-source creators, evaluate and enforce their GitHub (only for now) security posture at repository or organization level. Using policies defined using yml, GitArmor can run as CLI, GitHub action or GitHub App, to unify visibility into DevOps security posture and strengthen resource configurations as part of the development cycle.

Github: https://github.com/dcodx/gitarmor
</details>

<details>
  <summary>KernJC: Automated Vulnerable Environment Generation for Linux Kernel Vulnerabilities</summary>
  Linux kernel vulnerability reproduction is a critical task in system security. To reproduce a kernel vulnerability, the vulnerable environment and the Proof of Concept (PoC) program are needed. Most existing research focuses on the generation of PoC, while the construction of environment is overlooked. However, establishing an effective vulnerable environment to trigger a vulnerability is challenging. Firstly, it is hard to guarantee that the selected kernel version for reproduction is vulnerable, as the vulnerability version claims in online databases can occasionally be incorrect. Secondly, many vulnerabilities cannot be reproduced in kernels built with default configurations. Intricate non-default kernel configurations must be set to include and trigger a kernel vulnerability, but less information is available on how to recognize these configurations.



To solve these challenges, we propose a patch-based approach to identify real vulnerable kernel versions and a graph-based approach to identify necessary configs for activating a specific vulnerability. We implement these approaches in a tool, KernJC, automating the generation of vulnerable environments for kernel vulnerabilities. To evaluate the efficacy of KernJC, we build a dataset containing 66 representative real-world vulnerabilities with PoCs from kernel vulnerability research in the past five years. The evaluation shows that KernJC builds vulnerable environments for all these vulnerabilities, 32 (48.5%) of which require non-default configs, and 4 have incorrect version claims in the National Vulnerability Database (NVD). Furthermore, we conduct large-scale spurious version detection on kernel vulnerabilities and identify 128 vulnerabilities that have spurious version claims in NVD. To foster future research, we release KernJC with the dataset in the community.

Github: https://github.com/NUS-Curiosity/KernJC
</details>

<details>
  <summary>RedRays ABAP Code Scanner &amp; SAP Threat Modeling Builder</summary>
  RedRays is excited to present two open-source tools at BlackHat Asia, each designed to bolster security within SAP environments. The ABAP Code Scanner offers robust analysis of ABAP code, identifying security vulnerabilities, code quality issues, and best practice violations. During BlackHat Asia, we will introduce an open-source dataflow analysis feature to enhance the tool's ability to detect complex vulnerabilities by tracing data propagation through the code. Additionally, the SAP Threat Modeling Builder helps visualize interconnections across SAP landscapes, and we are pleased to announce upcoming support for SAP Java systems, which will be presented at the event. This extension will enable identification of security risks across both ABAP and Java-based SAP environments.

  Github: https://github.com/redrays-io/ABAP-Code-Scanner
  https://github.com/redrays-io/SAP-Threat-Modeling
</details>

<details>
  <summary>SCAGoat - Exploiting Damn Vulnerable and Compromised SCA Application</summary>
  SCAGoat is a deliberately insecure web application built to support hands-on learning and testing of Software Composition Analysis (SCA) tools. It allows users to explore vulnerabilities in Node.js and Java Springboot applications, featuring actively exploitable CVEs like CVE-2023-42282 and CVE-2021-44228 (log4j), and includes the compromised xz-java library. Designed for assessing various SCA and container security tools, SCAGoat's README includes reports from tools such as Semgrep, Snyk, and Endor Labs. Future research will incorporate additional compromised packages, enhancing its utility for testing SCA tools against supply chain attack scenarios.

  Github: https://github.com/toharzand/SCAgoat
</details>

<details>
  <summary>AI Wargame</summary>
  Come join a fun and educational attack and defence AI wargame. You will be given an AI chatbot. Your chatbot has a secret that should always remain a secret! Your objective is to secure your chatbot to protect its secret while attacking other players' chatbots and discovering theirs. The winner is the player whose chatbot survives the longest (king of the hill). All skill levels are welcomed, even if this is your first time seeing code, securing a chatbot, or playing in a wargame.

  Github not found
</details>

<details>
  <summary>Dradis Framework: Streamlined Collaboration and Reporting for Security Professionals</summary>
  In 2025, managing the information flow during assessments is just as important as finding vulnerabilities. Dradis Framework is an open-source communication and reporting tool for penetration testing teams designed to optimize your workflow, speed up reporting, and get rid of redundancies. Dradis combines results from scanners like Nessus, Burp Suite, and Nikto with manual findings and thorough attack narratives, facilitating smooth team-wide communication and an automated reporting process by centralising findings, notes, and evidence in a single portal.



Over the past ten years, Dradis has been battle-tested by thousands of infosec professionals, this community-driven effort has resulted in innovations like dynamic scanning tool mappings, a custom CSV importer, and new tool integrations. Learn how our most recent updates—which include in-app quality assurance workflows, easier deployment with Docker, and AI-driven enhancements—allow for the creation of reports faster and with greater quality. Come and learn how Dradis Framework works and how can it make your life a lot easier.

Github: https://github.com/dradis
</details>

<details>
  <summary>kntrl - Securing CI/CD runners through eBPF agent</summary>
  CI/CD pipelines are complex environments. This complexity requires methodical comprehensive reviews to secure the entire stack. Often a company may lack the time, specialist security knowledge, and people needed to secure their CI/CD pipelines. 

Realising these facts; cyberattacks targeting CI/CD pipelines has been gaining momentum, and attackers increasingly understand that build pipelines are highly-privileged targets with a substantial attack surface. 

We will share some of our observation through showing different flavours of attack on possible development pipelines, and introduce our tool to detect them.

Github: https://github.com/kondukto-io/kntrl
</details>

<details>
  <summary>Kong Loader: The hidden ART of rolling shellcode decryption</summary>
  Kong Loader is a completely new concept of loading shellcode. It prevents malware from being visible in memory *entirely* and *whatsoever*, even while executing commands, reinventing existing sleep mask techniques. For each assembly instruction, Kong Loader decrypts that specific assembly instruction, executes it, and encrypts it again. This means only the currently executing instruction is visible in memory.



It comes with dangerous benefits for offensive security experts, and with new complex challenges for defenders &amp; malware analysts. We'll cover that all, and Kong Loader will be published right after, so you can start experimenting with it yourself.

Github: https://github.com/tijme/kong-loader
</details>

<details>
  <summary>MobXplore</summary>
  MobXplore is a, frida based, open-source tool designed to assist security researchers, developers, and pentesters in performing comprehensive mobile application security assessments. Currently built for iOS devices, MobXplore will expand its capabilities to support Android devices, offering a versatile toolkit for mobile pentesting across multiple platforms. Presently it provides a comprehensive platform for performing iOS security testing. Built for pentesters and developers alike, it simplifies various stages of mobile application security testing, including device information retrieval, app management, IPA file handling, and dynamic analysis using Frida. MobXplore offers an intuitive yet powerful interface to explore, analyze, and secure mobile applications. It utilises Firda for most of its functionality, and it also intigrate other tools for some it's functionality. It streamlines the process of mobile application penetration testing by offering a powerful yet user-friendly interface packed with essential features. Whether you're assessing the security of your applications or probing for potential vulnerabilities, MobXplore brings everything you need under one cohesive interface.

  Github: https://github.com/enciphers-team/mobXplore
</details>

<details>
  <summary>R0fuzz: A Collaborative Fuzzer</summary>
  Industrial control systems (ICS) are critical to national infrastructure, demanding robust security measures. "R0fuzz" is a collaborative fuzzing tool tailored for ICS environments, integrating diverse strategies to uncover vulnerabilities within key industrial protocols such as Modbus, Profinet, DNP3, OPC, BACnet, etc. This innovative approach enhances ICS resilience against emerging threats, providing a comprehensive testing framework beyond traditional fuzzing methods.

  Github: https://github.com/AshwAthi8/R0fuzz
</details>

<details>
  <summary>DEBUGGING Apps like JTAG: A New Binary Emulator for Instruction-level Tracing and Analysis</summary>
  Simulation execution plays a vital role in computer security and boasts a wide range of applications, such as reversing obfuscated malware, fuzzing programs to identify vulnerabilities, or swiftly pinpointing the causes of program crashes. Unfortunately, the existing binary library emulators or tracing tools on the Android platform suffer from some issues: 1. Lack Runtime: For tools running on PC, this entails the manual simulation of JNI and Java methods. Examples include Unidbg, AndroidNativeEmu and Qiling; 2. Poor Stability: There are frequent direct crashes or infinite loops during simulation execution or tracing. For example, the Frida Stalker experiences such issues; 3. Low Performance: Inefficient tracing and fuzzing that can be frustrating.



As a result, we developed a binary library emulator that operates within apps called BRun, designed to monitor the instructions executed on the app, much like a JTAG in software. BRun is built on Unicorn, featuring comprehensive instruction implementation and enhanced stability in simulation execution. We designed a method for generating "virtual function" to replace the original function, enabling BRun to take over instruction execution when such a function is called. Additionally, we discovered a rarely used Unicorn API to resolve the memory mapping issue between the Host and Guest. Finally, to fully bridge the system environment between the Host and Guest, we designed two helpers: Syscall Helper and RuntimeCall Helper, both of which enhance the performance and stability of BRun's simulation execution.



BRun is applicable in scenarios such as tracing, debugging, fuzzing, and crash localization. We have also made new attempts at trace analysis, such as using static code analysis to assist with trace analysis and slicing traces through taint propagation.



This presentation will introduce some existing binary library emulators before detailing their implementation and elucidating their current challenges. Following this, we will introduce the architecture of BRun, along with the challenges faced in designing and implementing it. The audience will gain insight into the advantages of our emulator and its robust applications.

Github not found
</details>

<details>
  <summary>JARY - A Modular Data Correlation Engine</summary>
  JARY is a runtime for creating .jary rules to search and correlate log data from external sources. It allows users to define structured rules that filter, match, and analyze log entries to support data analysis and automation.

  Github: https://github.com/CTRLRLTY/JARY
</details>

<details>
  <summary>Mantis - Asset Discovery at Scale</summary>
  Mantis is an asset inventory framework that has the capability to distribute a single scan across multiple machines, provides easy customization, dashboard support, and advanced alerting capabilities. We have not reinvented the wheel. Rather, we have tried to design an architecture that provides the essential features for a framework that involves the complexity of integrating multiple tools that are outside our control.

  Github. https://github.com/PhonePe/mantis
</details>

<details>
  <summary>SmuggleShield 2.0 - Basic Protection Against HTML Smuggling</summary>
  <p><span>SmuggleShield (Protection against HTML smuggling attempts.)</span>

<span>SmuggleShield is a Chrome/Edge browser extension that provides protection against HTML smuggling attacks by detecting suspicious patterns in web content. It combines traditional pattern matching with machine learning capabilities to identify potential threats, featuring a customizable whitelist system to reduce false positives. The tool monitors webpage elements in real-time and can block malicious content while maintaining detailed logs of detected threats, making it particularly useful for security professionals during red/purple team exercises.</span>

<span>Reference - https://github.com/RootUp/SmuggleShield</span>

Key features:

- Real-time protection against HTML smuggling across all websites.
- User-friendly interface to manage whitelisted URLs and export logs for auditing.
- Runs in the background, monitoring content from page load to document completion.</p>

Github: https://github.com/RootUp/SmuggleShield
</details>

<details>
  <summary>Varunastra: Securing the Depths of Docker V2</summary>
  Docker has revolutionized how developers build, ship, and run applications, providing a consistent environment for software to run across various platforms. Its lightweight, containerized approach has made it an indispensable tool in modern DevOps practices. However, with its growing popularity, Docker has become a target for security vulnerabilities. Misconfigurations, exposed secrets, and unpatched dependencies are common issues that can lead to significant security breaches.



Introducing Varunastra, an innovative tool designed to enhance the security of Docker environments. Named after The Varunastra (वरुणास्त्र), it is the water weapon according to the Indian scriptures, incepted by Varuna, god of hydrosphere. Varunastra is engineered to detect and help mitigate vulnerabilities in Docker, ensuring robust security across all Docker containers and images.



Key Features of Varunastra:

1. Secret Detection

2. CVE Scanning

3. Dependency Confusion Prevention

4. Asset Extraction

5. SAST Scans of Source Code

6. HTML Report Generation



In a world where security threats are constantly evolving, Varunastra stands as a guardian, ensuring that your Docker environments remain fortified against leaked secrets, vulnerabilities, and dependency threats.

Github: https://github.com/redhuntlabs/Varunastra
</details>

<details>
  <summary>Circuit Breaker CTF</summary>
  "Circuit Breaker CTF" is a testbench for power industry security research. Our project is an end-to-end toolkit – introducing vulnerability research and security techniques for power devices, from the Energy Generation, to Transmission Lines, to Consumer &amp; Homes.

  Github not found
</details>

<details>
  <summary>KubeSF V1.2 - Kubernetes Security Posture Audit Suite</summary>
  KubeSF v1.2 (previously known as KubePWN) - A security audit suite for K8s is a powerful, lightweight and platform independent security tool designed to help security professionals and administrators to enhance and measure the security posture of on-prem Kubernetes clusters. Organizations are always committed to enhance the security of their containerized applications to mitigate potential vulnerabilities and to strengthen the overall security posture.



KubeSF framework encompasses a range of features and solutions, one of the prominent feature of KubeSF is that the security posture auditing is done at both pod level and namespace level and the relevant fix recommendations are also provided which eases the job of security professionals and administrators to assess and mitigate issues at a broader scope. Other prominent feature of KubeSF is that it performs static and runtime analysis with bare minimum permissions. KubeSF is capable of identifying and managing risky container capabilities which in turn prevents potential exploits. Our framework incorporates robust mechanisms to detect kernel exploits and privilege escalation vectors within containers to safeguard against potential container breakouts and privilege escalations. It also evaluates the permissions of service account tokens helping to ensure proper access controls, thus minimizing the potential of unauthorized access and damage to the cluster. It also has the capability to check for sensitive information in the container when abused may lead to unintended consequences. Moreover, it also provides granular security control auditing, allowing administrators to check, define and enforce customized security policies for pods. Furthermore, the KubeSF framework conducts thorough configuration audits of various protection mechanisms like Seccomp AppArmor, SELinux.  



The framework boasts a user-friendly interface and an easy-to-use dashboard which makes it simple for security professionals and administrators to assess the security posture of the cluster at their fingertips, with KubeSF one can assess the security posture of a kubernetes cluster and follow the recommendations mentioned to ensure that they are following all the industry best security practices. 



Overall, KubeSF is a swiss army knife for container security as it saves a lot of precious time, increases efficiency, enables a broad-scope driven approach allowing transparency into pod and namespace level security posture which helps in minimizing the risk of exploitation.

Github(previously known as KubePWN): https://github.com/deep1792/KubePwn
</details>

<details>
  <summary>NimPlant</summary>
  NimPlant is a light-weight first-stage command and control (C2) implant written in the Nim programming language. Since its release in 2023, it has been favored for its usability, slim implant profile, and evasive capabilities. The functionality is primarily aimed at early-access operations, but it packs powerhouse features such as Beacon Object File (BOF) support and inline execution of .NET assemblies. This allows operators to execute advanced tradecraft with a focus on operational security.



In 2024, NimPlant received a major update which included the addition of a Rust implant. This new implant matches the feature set of the original Nim-based implant, but has an increased focus on operational security and memory management. Furthermore, Rust has the performance advantage and has been adopted much more than Nim, which makes it easier to "blend in" with legitimate applications.



At Black Hat Asia Arsenal 2025, the design and architecture of NimPlant and the new Rust implant will be discussed. Offensive specialists will be provided with guidance and "pro tips" from the author on how to use the tool in offensive operations, while defensive specialists will be provided with guidance on how to identify and block this tool (and similar) in their network.

Github: https://github.com/chvancooten/NimPlant
</details>

<details>
  <summary>SadGuard: LLM-Assisted DevSecOps</summary>
  <div>SadGuard was inspired by the rising threat of supply chain attacks, leveraging advanced AI to secure software pipelines against malicious contributions in pull requests. It uses intelligent code diff analysis, sandboxed executable behaviour monitoring, and entropy scanning of binaries to detect and mitigate malicious patterns before deployment.
Designed as a self-hosted tool, SadGuard provides proactive defense by embedding itself into the CI/CD process. It intelligently identifies vulnerabilities, flags obfuscation, and monitors suspicious runtime behavior. The modular architecture allows for future expansion, including support for additional LLMs and scoring systems for prioritized response.
SadGuard supports integration with GitHub via webhooks and offers seamless local deployment for complete data control. It combines intelligent detection with runtime observation to secure software pipelines while maintaining operational privacy. Built with a focus on detecting and preventing supply chain compromises, it helps harden software repositories against modern threats.
</div>

Github: https://github.com/DakshRocks21/SadGuard
</details>

<details>
  <summary>sql-data-guard: Safety Layer for LLM Database Interactions</summary>
  <p>SQL is the go-to language for performing queries on databases and for a good reason - it's well known, easy to use and pretty simple. However, it seems that it's as easy to use as it is to exploit and SQL injection is still one of the most targeted vulnerabilities especially nowadays with the proliferation of "natural language queries" harnessing LLM power to generate and run SQL queries.

To help solve this problem, we developed sql-data-guard, an open-source project designed to verify that SQL queries access only the data they are allowed to. It takes a query and a restriction configuration, and returns whether the query is allowed to run or not. Additionally, it can modify the query to ensure it complies with the restrictions. sql-data-guard has also a built-in module for detection of malicious payloads, which it can report on and remove malicious expressions before query execution.

sql-data-guard is particularly useful when constructing SQL queries with Large Language Models (LLMs), as such queries can't run as prepared statements. Prepared statements secure a query's structure, but LLM-generated queries are dynamic and lack this fixed form, increasing SQL injection risk. sql-data-guard mitigates this by inspecting and validating the query content.

By verifying and modifying queries before they are executed, sql-data-guard helps prevent unauthorized data access and accidental data exposure. Adding sql-data-guard to your application can prevent or minimize data breaches and sql-injection attacks impact, ensuring that only permitted data is accessed. 

Connecting LLMs to SQL databases without strict controls can risk accidental data exposure, as models may generate SQL queries that access sensitive information. OWASP highlights cases of poor sandboxing leading to unauthorized disclosures, emphasizing the need for clear access controls and prompt validation. Businesses should adopt rigorous access restrictions, regular audits, and robust API security, especially to comply with privacy laws and regulations like GDPR and CCPA, which penalize unauthorized data exposure.</p>

Github: https://github.com/ThalesGroup/sql-data-guard
</details>

<details>
  <summary>SupplyShield: Protecting your software supply chain</summary>
  SupplyShield is a comprehensive supply chain security framework aimed at defending against the increasingly sophisticated attacks posed by software supply chain vulnerabilities. With numerous organizations hosting hundreds of micro-services and thousands of builds occurring daily, effectively monitoring the software supply chain to construct the final application becomes a complex challenge. This is where SupplyShield can assist any organization in seamlessly integrating this framework into their Software Development Lifecycle (SDLC) to ensure software supply chain security.



The current framework version is predominantly designed for the AWS environment. Any organization utilizing AWS infrastructure can seamlessly implement this framework with minimal effort via AWS CloudFormation templates to enhance the security of their supply chain. The framework mainly focuses on generating and maintaining a Software Bill of Materials (SBOM) and performing Software Composition Analysis (SCA) for all the micro-services within an organization. The scans are event-driven, targeting the final microservice image pushed into AWS ECR. As a result, it generates an SBOM of base image binaries and 3rd-party packages introduced by developers, and performs SCA on top of that. This approach provides a comprehensive view of the software components involved in the overall development of a micro service.



Built with scalability in mind, SupplyShield is capable of generating an SBOM and performing SCA in a CI/CD environment where thousands of builds take place daily. SupplyShield enables the rapid detection of zero-day vulnerabilities, such as the log4j exploit, even for organizations with over 100 micro-services, significantly reducing the Mean Time To Detect (MTTD) to mere minutes. This significantly simplifies the tasks of both security engineers and developers in identifying and managing patches for events like the log4j vulnerability. The framework also offers a dashboard for developers and security engineers, presenting relevant metrics and actionable insights.

Github: https://github.com/supplyshield/supplyshield
</details>

<details>
  <summary>Blackdagger</summary>
  Blackdagger represents a significant advancement, offering a comprehensive solution for orchestrating complex workflows in DevOps, DevSecOps, MLOps, MLSecOps, and Continuous Automated Red Teaming (CART) environments.



At its core, Blackdagger simplifies the management and execution of intricate workflows through its user-friendly approach and powerful functionality. Leveraging a declarative YAML format, Blackdagger enables users to define automation pipelines using a Directed Acyclic Graph (DAG), facilitating clear and concise expression of task dependencies and execution logic.



What sets Blackdagger apart is its simplicity and versatility. Unlike traditional cron-based schedulers or workflow orchestration platforms, Blackdagger eliminates the need for extensive scripting or coding. With a built-in Web UI, users can easily manage, rerun, and monitor automation pipelines in real-time, streamlining the workflow management process. Additionally, Blackdagger offers native Docker support, enabling seamless integration with containerized environments, and a versatile toolset for task execution, including making HTTP requests and executing commands over SSH.

Blackdagger stands out due to its comprehensive features aimed at simplifying and enhancing automation workflow management. 



Highlights of Blackdagger



* Single binary file installation

* Declarative YAML format for defining DAGs

* Web UI for visually managing, rerunning, and monitoring pipelines

* Use existing programs without any modification

* Self-contained, with no need for a DBMS

* Suitable for Continuous Red Teaming (CART)

* Suitable for DevOps and DevSecOps

* Suitable for MLOps and MLSecOps

Github: https://github.com/ErdemOzgen/blackdagger
</details>

<details>
  <summary>From Mapping to Mitigation: OSS-Driven Attack Resistance</summary>
  <p><span>We'll cover the full lifecycle—from mapping using a range of discovery tools (subfinder, dnsx, etc.) and enriching with tools like httpx and katana, to scanning and triaging with Nuclei. Plus, we'll touch on integrated ticketing in nuclei, regression handling, and our community-led inventory of actionable, exploitable vulnerability checks, misconfigurations, DAST, auditing, and more.</span></p>

  Github not found
</details>

<details>
  <summary>Kubernetes Goat: A Hands-on Interactive Kubernetes Security Playground</summary>
  <p>Containers are everywhere, and Kubernetes has become the de facto standard for deploying, managing, and scaling containerized workloads. Yet security issues continue to emerge in the wild daily, ranging from simple misconfigurations to sophisticated attacks. In this session, I'll introduce Kubernetes Goat, an interactive security playground designed to help you master the skills needed to hack and secure your Kubernetes clusters and container workloads.

Kubernetes Goat is an open-source platform featuring intentionally vulnerable scenarios within a Kubernetes cluster. From common vulnerabilities to notorious real-world attack patterns, each scenario is crafted to reflect actual security challenges - not theoretical simulations. Join me, the creator of Kubernetes Goat, as we dive deep into cluster vulnerabilities and emerge with practical defense strategies. Get ready to hack, learn, and shield your clusters!</p>

Github: https://github.com/madhuakula/kubernetes-goat
</details>

<details>
  <summary>MicroSleuth: Novel Proof-of-Concept Monitoring on Embedded Systems</summary>
  Embedded systems are specialized computing units that are integral to a variety of sectors, from consumer wearables to industrial controls. The ubiquity of these devices in our electronic landscape has made them prime targets for cyber threats, evidenced by historical attacks on operational technologies, such as the infamous Stuxnet against nuclear facilities. This underscores the critical importance of endpoint detection and response for embedded systems.



Endpoint detection of embedded systems involves specialized techniques and tools aimed at analyzing data from custom devices like routers, smart wearables, and the broader range of IoT products. Among the arsenal available easily or cheaply, there are none generally suited for embedded systems. Thus our proposed solution steps in to fill a needed niche that has no easy solution. Furthermore with the ongoing digitalization, more and more embedded systems are being put into deployment with little security built in mind.



In response to the growing need for robust embedded systems end-point detection and response, we introduce MicroSleuth: a proof-of-concept Raspberry Pi Pico-based hardware tool engineered for forensic scrutiny of embedded systems. MicroSleuth is designed for interfacing with the SWD debug outputs of an embedded system, enabling it to acquire and scrutinize flash memory for malicious code patterns. It goes a step further by cross-referencing the expected debug outputs with the actual operational behavior of the system, ensuring its proper function and security.

Github not found
</details>

<details>
  <summary>CompatrIoT</summary>
  CompartIoT is an open-source hardware security training platform that serves as a dedicated target for learning real-world hardware security techniques. Built around dual microcontrollers (STM32 and ESP32) design, this training board enables security researchers, hobbyists, and students to practice protocol analysis, firmware exploitation, and hardware security assessment through comprehensive hands-on labs.

  Github: https://github.com/traboda/CompatrIoT
</details>

<details>
  <summary>AI Goat: Learning to Exploit Vulnerabilities in AI Systems</summary>
  AI Goat is an intentionally vulnerable, open-source AI infrastructure designed to educate security enthusiasts and penetration testers about AI-specific vulnerabilities, aligning with the OWASP ML Top 10. This session will introduce AI Goat, demonstrate deployment methods, and expose participants to various vulnerabilities they will learn to exploit. By engaging directly with AI Goat, attendees will gain hands-on experience in recognizing and mitigating risks in AI systems, enhancing their understanding of the AI threat landscape.

  Github: https://github.com/dhammon/ai-goat
</details>

<details>
  <summary>FZAI Fuzzer - Behind AI Lines: Disrupting LLM Alignment to Build Bombs, Leading to Enhanced Security</summary>
  <p>Who would have thought that prompting LLMs with questions about building bombs could actually strengthen their security? As these models become foundational to our digital tools—much like a new operating system—they still lack many essential security features. That's where our approach steps in: by understanding and disrupting their core alignments.

Leveraging our extensive experience in vulnerability research, we apply zero-day discovery techniques to generative AI. We've developed a systematic method to breach the defenses of the latest LLM models, accompanied by a new open-source fuzzing infrastructure that makes jailbreaking not only efficient but also integral to crafting detection-based solutions that enhance LLM security.

Our research goes deeper, examining how manipulating different neuron layers affects alignment. By dissecting these layers, we uncover the mechanics of LLM behavior and find ways to adjust their alignments for greater security.
</p>

Github: https://github.com/cyberark/FuzzyAI
</details>

<details>
  <summary>LLMobile - Mobile Security with AI Insights</summary>
  In the era of digital transformation, mobile applications have become integral to the way businesses operate, engage with customers, and deliver services.

 Mobile apps handle vast amounts of sensitive information, such as user data, payment details, and authentication tokens.

Traditional mobile security scanners primarily rely on static code analysis, searching for known vulnerability patterns or signatures. While effective to an extent, these tools often generate high false positives and may miss context-dependent vulnerabilities that don't align with predefined rules. In contrast, our tool leverages LLMs to intelligently reduce false positives, honing in on genuine security issues with greater accuracy and depth.

With a web dashboard, this tool provides a seamless, user-friendly interface that enhances efficiency, enabling teams to swiftly detect and address critical vulnerabilities. This powerful combination ensures a smarter, more proactive approach to mobile application security.

Developed at https://adeosecurity.com/
</details>

<details>
  <summary>MissionEvasion</summary>
  MissionEvasion is a proof-of-concept tool designed for malware evasion on Windows systems. It leverages advanced techniques like process hollowing and injection to bypass detection mechanisms by executing malicious binaries from the Windows registry. The tool stores the malicious payload in the Windows registry as bytecode, retrieving it directly into memory, and executes it within the context of a legitimate process. This stealthy method is aimed at evading signature-based detection systems and can be used to study potential evasion techniques for red teaming exercises.

  Github not found
</details>

<details>
  <summary>sisakulint - CI-Friendly static linter with SAST, semantic analysis for GitHub Actions</summary>
  In recent years, attacks targeting the Web Application Platform have been increasing rapidly.

sisakulint is a static and fast SAST for GitHub Actions. This great tool can automatically validate yaml files according to the guidelines in the security-related documentation provided by GitHub! It also includes functionality as a static analysis tool that can check the policies of the guidelines that should be set for use in each organization. These checks also comply with the Top 10 CI/CD Security Risks (https://owasp.org/www-project-top-10-ci-cd-security-risks/) provided by OWASP. It implements most of the functions that can automatically check whether a workflow (https://docs.github.com/ja/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions ) that meets the security features supported by github has been built to reduce the risk of malicious code being injected into the CI/CD pipeline or credentials such as tokens being stolen. It does not support inspections that cannot be expressed in YAML and "repository level settings" that can be set by GitHub organization administrators.

It is intended to be used mainly by software developers and security personnel at user companies who work in blue teams. It is easy to introduce because it can be installed from brew.

It also implements an autofix function for errors related to security features as a lint.

It supports the SARIF format, which is the output format for static analysis. This allows Review Dog to provide a rich UI for error triage on GitHub. 

 ref: https://github.com/reviewdog/reviewdog?tab=readme-ov-file#sarif-format

 https://github.com/ultra-supara/sisakulint/pull/91/checks?check_run_id=32750598299



 Main Tool features: 

 	id collision detection

 		Environment variable names collision

 		docs : https://sisakulint.github.io/docs/idrule/

 		github ref https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#using-a-specific-shell

 	Hardcoded credentials detection  by rego query language

 	 docs : https://sisakulint.github.io/docs/credentialsrule/

 	commit-sha rule

 		docs : https://sisakulint.github.io/docs/commitsharule/

 		github ref https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

 	premissions rule

 	 docs : https://sisakulint.github.io/docs/permissions/

 	 github ref : https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#permissions

  workflow call rule

   docs : https://sisakulint.github.io/docs/workflowcall/

   github ref : https://docs.github.com/en/actions/sharing-automations/reusing-workflows

  timeout-minutes-rule

   docs : https://sisakulint.github.io/docs/timeoutminutesrule/

   github ref : https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes

   github ref : https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes

   Github above <3 to them.
</details>

<details>
  <summary>Falco Action to the Rescue: Sniffing Out Sneaky Supply Chain Attacks in Your GitHub Action Workflows!</summary>
  Continuous Integration and Continuous Deployment (CI/CD) pipelines are essential in modern software development, enabling rapid code integration, testing, and deployment. Achieving deep visibility within these pipelines is critical to ensure the code released to production is secure and reliable.



Falco-action leverages Falco, an open-source runtime security tool from CNCF, to detect threats and malicious activity within CI/CD pipelines. With its exceptional visibility into Linux kernel system calls, falco-action integrates seamlessly into GitHub workflows to monitor the runtime behavior of the runner server. By capturing key runtime events, such as suspicious connections and file accesses, Falco acts as a dependable ally in identifying anomalous behavior in CI/CD environments.



We'll guide you through real-world scenarios, demonstrating how falco-action can be used in GitHub Actions pipelines to detect and address malicious behavior effectively.

Github: https://github.com/falcosecurity/falco-actions
</details>


<details>
  <summary>KubeAPI-Inspector:discover the secrets hidden in apis</summary>
  Due to the rapid development of cloud-native technologies, an increasing number of popular applications are extending Kubernetes' control plane functionalities through extension apiserver.

With Kubernetes being centered around a declarative API, we have designed a tool specifically for this scenario. This tool aims to efficiently and automatically discover hidden vulnerable APIs within the cluster.

Additionally, we will publish a vulnerability pattern for the first time,which occurs when the golang struct embedding and promoted methods are used improperly, and demonstrate this problem through a workshop, this problem which could potentially lead to API endpoint authentication failures, thereby jeopardizing the entire cluster.

Github not found

</details>

<details>
  <summary>Vulnerability Detection Specific to Web Applications by LLM Agent</summary>
  In recent years, research on automating penetration testing and software testing using LLMs has been actively conducted. For example, the paper "PentestGPT: An LLM-empowered Automatic Penetration Testing Tool" attempts to automate penetration testing primarily in the network domain and has successfully performed complete penetration testing on servers with Easy and Medium difficulty levels on Hack The Box. Additionally, the paper "LLM Agents can Autonomously Hack Websites" examines whether a black-box LLM such as GPT-4 can exploit common vulnerabilities like SQL injection in actual websites. This research demonstrates that models like GPT-4 can identify vulnerabilities in real-world websites and exploit complex vulnerabilities without prior vulnerability information.

Inspired by these approaches, we have developed a tool called BugNet, which is designed to detect vulnerabilities unique to web applications by leveraging an LLM. Currently, tools like Zap and BurpSuite can detect common vulnerabilities such as XSS and SQL injection through their scanning capabilities. However, these tools struggle to detect web application-specific vulnerabilities, such as privilege escalation, tampering with purchase information, and user impersonation. Our tool focuses on detecting these specific web application vulnerabilities, which are challenging to identify with existing scanning tools, rather than focusing on general vulnerabilities like SQL injection and XSS, by utilizing an LLM agent.

Pentest-GPT paper: https://arxiv.org/abs/2308.06782
</details>

<details>
  <summary>Chakshu</summary>
  Problem Statement



Network assessments, penetration testing, and vulnerability scanning are critical tasks for security professionals, network administrators, and penetration testers. However, the use of multiple command-line interface (CLI) tools to carry out these tasks often leads to fragmented workflows, complexity in tool management, and inefficient scanning processes. Managing different CLI tools, interpreting results from various formats, and configuring repetitive tasks can be time-consuming and prone to error. Additionally, security experts must often manually handle tasks like scheduling scans, integrating proxy chains, managing distributed scanning, and ensuring easy export of results. As the demand for more streamlined, integrated, and automated solutions increases, there is a clear need for a unified tool that simplifies these operations while maintaining powerful features.





Tool Abstract



Network_Scan_hub  is an open-source graphical user interface (GUI) designed to bring together multiple command-line network scanning tools, such as Naabu, Nmap, RustScan, and others, into a cohesive platform. This tool enhances the user experience by offering a simple, streamlined interface for managing and executing network scans, automating repetitive tasks, and presenting results in a user-friendly format. By consolidating several key scanning functionalities into one platform, Network_Scan_hub makes it easier for security professionals to carry out comprehensive network assessments while minimizing their interaction with the command line. This tool supports a wide range of network scanning features, including vulnerability checks, scan scheduling, proxy chaining, and agent-based scanning. It is designed to simplify complex workflows, improve productivity, and make network security assessments more accessible to both experienced professionals and newcomers alike.

Github???: https://github.com/Insider-HackZ/Network-Scanner-GUI
</details>

<details>
  <summary>BOAZ: Development of a Multilayered Evasion Tool and Methodology</summary>
  BOAZ (Bypass, Obfuscate, Adapt, Zero-Trust) evasion was inspired by the concept of multi-layered approach which is the evasive version of defence-in-depth first proposed by  at BH USA14 [1]. BOAZ was developed to provide greater control over combinations of evasion methods, enabling more granular evaluations against antivirus and EDR. It is designed to bypass both before and during execution detections that span signature, heuristic and behavioural detection techniques [2]. 



BOAZ supports both x86/x64 binary (PE) or raw payload as input and output EXE or DLL. It has been tested on separated Window-11 Enterprise VMs (version: 22H2, 22621.1992) with 14 Desktop AVs installed include Windows Defender, Norton, BitDefender and ESET. The design of BOAZ evasion is modular, so users can add their own toolset or techniques to the framework. One advantage of this approach is that if a specific technique's signature become known to antivirus, researchers can easily adjust the technique to verify it and either improve or swap a new technique to that detection. This process is described as a query-modify-query attack process, where the attacker can improve based on feedback from black-box engines until their sample is fully undetectable (FUD) [3]. 



BOAZ is written in C++ and C and uses Python3 as the main linker to integrate all modules.  There have been significant improvements implemented since its inception. The new features of the BOAZ evasion tool, set to be released at BH Asia 2025, include two novel process injection primitives, along with newly implemented loaders and behavioural evasion techniques.

Github: https://github.com/thomasxm/BOAZ
</details>


<details>
  <summary>MachOpen: A High-Performance Lightweight Reverse Analysis Tool for iOS Applications</summary>
  <p>Existing static reverse tools for iOS applications mainly meet two problems: 1)Require high memory and CPU resources. 2) Lacks portability and flexibility. Thus, crashes often occur when analyzing large executable files, due to complex calculations, heavy rendering and constantly updated iOS features.

We proposed MachOpen, a portable and efficient lightweight reverse tool for iOS applications. MachOpen implements comprehensive iOS features in virtual environments, including basic dynamic mechanisms (symbol lazying binding, objc_msgSend, async_dispatch and so on) and new features , e.g, it supports recognizing stubs with OC selector for message sending, since Apple deduplicates _objc_msgSend setup infrastructure to implements size optimization in more advanced versions.

MachOpen applies a novel hierarchical structure for stack and heap during simulation. This multi-level design enables memory sharing when performing large instruction-level calculations. Compared to Unicorn, MachOpen greatly reduces the memory usage and pressure of garbage collection. Furthermore, based on high concurrent coroutine, it achieves more efficient analysis during complex data flow or control flow analysis.

MachOpen has a built-in web frontend to support display and debugging requirements. At the same time, it also provides clear and flexible CLI commands usage for advanced users, allowing decoupling the running process and implementing specific analysis without redundancy.</p>

Github not found
</details>

<details>
  <summary>MORF - Mobile Reconnaissance Framework</summary>
  <p><span>MORF - Mobile Reconnaissance Framework is a powerful, lightweight, and platform-independent offensive mobile security tool designed to help hackers and developers identify and address sensitive information within mobile applications. It is like a Swiss army knife for mobile application security, as it uses heuristics-based techniques to search through the codebase, creating a comprehensive repository of sensitive information it finds. This makes it easy to identify and address any potentially sensitive data leak.</span>

<span>One of the prominent features of MORF is its ability to automatically detect and extract sensitive information from various sources, including source code, resource files, and native libraries. It also collects a large amount of metadata from the application, which can be used to create data science models that can predict and detect potential security threats. MORF also looks into all previous versions of the application, bringing transparency to the security posture of the application.</span>

<span>The tool boasts a user-friendly interface and an easy-to-use reporting system that makes it simple for hackers and security professionals to review and address any identified issues. With MORF, you can know that your mobile application's security is in good hands.</span>

<span>Overall, MORF is a Swiss army knife for offensive mobile application security, as it saves a lot of time, increases efficiency, enables a data-driven approach, allows for transparency in the security posture of the application by looking into all previous versions, and minimizes the risk of data breaches related to sensitive information, all this by using heuristics-based techniques.</span></p>

Github: https://github.com/amrudesh1/MORF
</details>

<details>
  <summary>Plaguards: Open Source PowerShell Deobfuscation and IOC Detection Engine for Blue Teams.</summary>
  Plaguards was developed to address a critical need within Incident Response (IR) teams, specifically in handling obfuscated PowerShell scripts—a frequent component in modern malware and ransomware attacks that severely threaten business operations. Despite the availability of numerous deobfuscation tools for JavaScript, there is a notable shortage of static deobfuscation resources for PowerShell, especially amidst the increasing trend of fileless PowerShell-based attacks observed throughout 2024. This gap has left IR teams without effective tools to manage these high-stakes threats.



Most existing tools only focus on detecting obfuscated PowerShell rather than fully deobfuscating it, leaving a crucial aspect of analysis unaddressed. Plaguards fills this void, enabling automated deobfuscation specifically tailored to PowerShell scripts. It empowers IR teams to swiftly parse through obfuscated lines, identify embedded Indicators of Compromise (IOCs) like IP addresses and URLs, and determine if they represent legitimate threats or false positives.



Beyond deobfuscation, Plaguards enhances the overall response workflow by providing templated PDF reports, documenting each deobfuscated line and cross-referencing IOCs with threat intelligence. This capability not only aids in real-time threat assessment but also supports IR teams by delivering comprehensive, actionable insights in a clear and organized format.

Github: https://github.com/baycysec/plaguards
</details>


<details>
  <summary>Decoy Mutex</summary>
  Tool Name: Decoy-Mutex



A Windows tool for creating decoy mutexes (Fake Infection Markers) associated with ransomware simulations. Ransomware checks for the presence of its related mutex to determine whether the system is already infected. It doesn't infect the system if it locates the mutex.

Github: https://github.com/ScarredMonk/Decoy-Mutex
</details>

<details>
  <summary>Intro to CICDGuard - How to have visibility and security OF CICD ecosystem</summary>
  CICDGuard is a graph based CICD ecosystem visualizer and security analyzer, which - 

1) Represents entire CICD ecosystem in graph form, providing intuitive visibility and solving the awareness problem

2) Identifies common security flaws across supported technologies and provides industry best practices and guidelines for identified flaws adhering to OWASP CICD Top10 vulnerabilities

3) Identifies the relationship between different technologies and demonstrates how vulnerability in one component can affect one or more other technologies

Technologies supported - GitHub, GitHub Action, Jenkins, JFrog, Spinnaker, Drone



CICD platforms are an integral part of the overall software supply chain and it processes a lot of sensitive data, compromise of which can affect the entire organization. Security IN CICD is a well discussed topic, security OF CICD deserves the same attention. One of the challenges with security OF CICD, like most areas of security, is the lack of visibility of what actually makes a CICD ecosystem. Security starts with being aware of what needs to be secure.

Github: https://github.com/varchashva/CICDGuard
</details>

<details>
  <summary>KernelGoat</summary>
  "KernelGoat is a 'Vulnerable by Design' Linux kernel environment to learn and practice Kernel security issues"



There are a lot of resources, playgrounds, CTF's for user-land based exploitation scenarios. However when it comes to Kernel based exploitation, especially Linux there aren't many vulnerable by design labs.



The setup steps are very simple and do not require the user to spend enormous time on setup and instead focus on exploiting the vulnerability itself.



Few of vulnerabilities the users can get experience exploiting are



Arbitrary Read

Stack Overflow

Null pointer dereference 

Race condition

Use After Free

Heap Overflow

Off-By-One Vulnerability

Uninitialized Stack Variables

Double Free



This tool is being developed by students from T.John Engineering College Bangalore. Divya M, Archana BS, Allen Sam and Sujitha Palanadan

Github: https://github.com/Rnalter/KernelGoat
</details>

<details>
  <summary>RedInfraCraft : Automate Complex Red Team Infra</summary>
  RedInfraCraft is a solution for automating the deployment of powerful red team infrastructures. It streamlines the setup and management of : 



- Individual Red Team Components (C2, Payload, Redirector Server etc.)

- On-premise / Cloud services re-director support

- Complete Red Team Infrastructure (Redirector  Load Balancer  C2, Payload server, phishing server etc)

- Phishing Operations

- Infrastructure deployment support in AWS, Azure &amp; GCP Cloud including multi-cloud support.



Dilute your time to setup Red Team Infrastructure in 5 minutes with RedInfraCraft

Github: https://github.com/RedTeamOperations/Red-Infra-Craft
</details>

<details>
  <summary>Silver SAML Forger: Tooling to craft forged SAML responses from Entra ID</summary>
  Silver SAML Forger is a tool developed to PoC SAML response forging, also known as Silver SAML and Golden SAML attacks, against applications federated to Entra ID for authentication using the SAML standard. The tool goes along with research into the vulnerabilities that can present in cloud identity providers, such as Entra ID, where if an attacker has access to the private key material Entra ID uses for SAML response signing, that the target applications may be susceptible to these forging attacks.



While Entra ID protects the private key if generated internally, as it cannot be exported, in the real-world organizations follow bad habits that may leave sensitive private key material available to an attacker. These sorts of habits have been observed by the research team that developed the Silver SAML Forger. Using this tool in combination with tools such as Burp Suite, you can demonstrate forging access to a target application. If the application supports certain types of SAML integrations, the identity provider will have no visibility into the authentication – you could think of these attacks as Kerberos Golden-ticket type attacks.



The tool requires the signing certificate to use, the username that is target for impersonation, and some basic federation information about the target application that can be derived from a few different methods.

Github: https://github.com/Semperis/SilverSamlForger
</details>

<details>
  <summary>Casino Heist: Master the Art of Solidity Smart Contract Security</summary>
  Ethereum was the first blockchain to discover and implement smart contracts as part of the functionalities of blockchain, which unlocked more usage of blockchain and led to the explosion of decentralized Applications (dApps). Over the past few years, numerous exploits have resulted in millions of dollars being stolen from various protocols. You name it, reentrancy attacks, integer overflow &amp; underflow, access control vulnerabilities, and more. Let's be realistic, identifying vulnerabilities in a smart contract and ensuring its security is a significant challenge because you not only need to understand how the exploits work and how to mitigate them, but you also need hands-on experience to truly grasp the process, right?



Casino Heist tackles this challenge by offering a platform where developers and auditors can investigate vulnerabilities within Solidity code. Built on a private blockchain by ParadigmXYZ and TCP1P, we provide an engaging environment for users to explore vulnerabilities hidden within smart contracts. The challenges range from basic to simplified real-world hacks, and we offer mitigation strategies for every identified vulnerability. Additionally, our walkthroughs guide participants through each heist until completion. We also welcome you to join us in contributing challenges or walkthroughs, helping to expand the experience for the entire community.



With the combination of learning the fundamentals of vulnerabilities, gaining hands-on experience in exploiting them, and understanding their mitigations, our mission is to cultivate developers with a strong grasp of security—whether you aim to become a smart contract auditor or simply want to add smart contract security to your skillset. If that sounds like you, this is the perfect place to start your journey!

Github: https://github.com/Kiinzu/Casino-Heist
</details>

<details>
  <summary>FireTail - inline open-source API security</summary>
  FireTail enables you to solve all the most critical problems facing APIs today with full blocking capabilities to solve the root causes of API data breaches - flaws at the application and business logic layer in authentication, authorization and data handling.

  Github: https://github.com/firetail-io
</details>

<details>
  <summary>Halberd : Multi-Cloud Security Testing Tool</summary>
  Tired of juggling multiple tools for cloud security testing? Meet Halberd - an advanced open-source security testing tool that lets you execute sophisticated attack techniques across Entra ID, M365, AWS, and Azure through a sleek web interface. Whether you're red teaming enterprise clouds or doing Friday afternoon security validation, Halberd has your back.



Created to democratize cloud security testing, Halberd eliminates the complexity of setting up and running advanced attack techniques. No more context switching between tools or wrestling with complicated setups - just pick a technique (or an advanced playbook) and execute.

Github: https://github.com/vectra-ai-research/Halberd
</details>

<details>
  <summary>SHIVA Spampot: Actionable Spam and Phishing Intelligence</summary>
  Spam and phishing emails remain among the most common vectors used by threat actors for delivering malicious URLs and attachments. A spam email honeypot (spampot) offers an excellent opportunity to observe and gather intelligence about these attack vectors. We are releasing an open-source honeypot, SHIVA (Spam Honeypot with Intelligent Virtual Analyzer), designed specifically for capturing and analyzing spam interactions at cloud scale. The honeypot presents itself as a fully functional and open SMTP server. By deploying this honeypot, researchers and organizations can analyze and gather real-time threat intelligence on spam. Analysis of captured data can provide information on phishing attacks, scamming campaigns, malware campaigns, and spam botnets. This will enable the organizations to identify emerging threats and improve their defensive strategies. We detail the architecture and implementation of the honeypot, along with case studies showcasing its effectiveness in enriching threat intelligence.

  Github: https://github.com/shiva-spampot/shiva
</details>

<details>
  <summary>Foundpy: Foundry-like Interface for Interacting with Ethereum Application in Python</summary>
  <p><span>Foundpy is a Foundry-like interface for interacting with the Ethereum application as a single Python module. It's designed to be easy to use, just like Foundry's commands, but no installation of Foundry is required. This provides a streamlined experience for developers and security researchers.</span>

<span>Beyond basic Foundry replication, Foundpy incorporates specialized features designed for Capture The Flag (CTF) challenges. Which is inspired by the popular pwntools library, the combination of Foundry's friendly interface and the ease of use of CTF framework like pwntools is what makes it the best tool for beginners to learn blockchain security.</span></p>

Github: https://github.com/Wrth1/foundpy
</details>

<details>
  <summary>Stowaway: Multi-hop Proxy Tool for pentesters</summary>
  Stowaway is a multi-level proxy tool written in the go language and designed for penetration testers and security researchers. Attackers can use Stowaway to construct their own tree network in a highly restricted intranet environment so that the attacker's external traffic can reach the core network through the layers of proxies of multiple Stowaway nodes. While breaking through network access restrictions, Stowaway can also help attackers hide their own traffic and better lurk in the intranet. In addition, attackers can also use the terminal interface and various auxiliary functions provided by Stowaway to more easily manage the entire tree network and improve the efficiency of penetration testing.

  Github: https://github.com/ph4ntonn/Stowaway
</details>


<details>
  <summary>Agneyastra - Firebase Misconfiguration Detection Toolkit V2</summary>
  Firebase, a versatile platform by Google, powers countless web and mobile applications with its extensive suite of services including real-time databases, authentication, cloud storage, and hosting. Its ubiquity and ease of use make it a popular choice among developers, but also a prime target for misconfigurations that can lead to significant security vulnerabilities.



Agneyastra, a mythological weapon bestowed upon by the Agni (fire) Dev (god) is a divine weapon associated with the fire element. Presenting Agneyastra, a cutting-edge tool designed to empower bug bounty hunters and security professionals with unparalleled precision in detecting Firebase misconfigurations. With its comprehensive checks covering all of Firebase services, an intelligent correlation engine, and automated report generation, Agneyastra ensures that no vulnerability goes unnoticed, turning the tides in your favor.



Key Features:



1. Checks for Misconfiguration in all the Firebase services.

2. Intelligent Correlation Engine.

3. POC and Report Creation.

Github: https://github.com/JA3G3R/agneyastra
</details>


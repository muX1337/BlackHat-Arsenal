<details>
  <summary>A.I.G（AI-Infra-Guard）</summary>
  <p><span>A.I.G (AI-Infra-Guard) is a comprehensive, intelligent, and user-friendly AI red teaming platform developed by Tencent Zhuque Lab, designed to provide users with a one-stop solution for AI security risk self-assessment.</span>

<span>Key Features and Capabilities:</span>

<span>AI Infra Scan: Precisely identifies over 30 AI framework components, covering nearly 400 known CVE vulnerabilities in frameworks like Ollama, ComfyUI, and vLLM.</span>
<span>MCP Scan: Driven by an AI Agent, it can detect 9 major categories of MCP security risks, such as tool poisoning and indirect prompt injection, and supports both source code analysis and remote URL scanning.</span>
<span>Jailbreak Evaluation: Includes multiple high-quality assessment datasets and jailbreak attack algorithms. It can rapidly generate LLM red teaming reports and supports exporting detailed reports for security alignment and guardrail reinforcement</span></p>
</details>

<details>
  <summary>AI Wargame</summary>
  Come join a fun and educational attack and defence AI wargame. You will be given an AI chatbot. Your chatbot has a secret that should always remain a secret! Your objective is to secure your chatbot to protect its secret while attacking other players' chatbots and discovering theirs. The winner is the player whose chatbot survives the longest (king of the hill). All skill levels are welcomed, even if this is your first time seeing code, securing a chatbot, or playing in a wargame.



Right at the start, there will be a briefing to show how to play in the wargame. Knowledge of the OpenAI Python SDK helps but is not a requirement. Each player has access to their chatbot source code repository where they can run, test, debug and push their changes.
</details>

<details>
  <summary>Beyond the Static rules: Cloud-Native Anomaly Detection with Kubescape</summary>
  As cloud-native environments scale to hundreds or even thousands of microservices, maintaining effective runtime detection becomes one of the hardest problems in security engineering. Traditional rule-based tools like Falco and Tetragon require constant configuration and tuning. Static detection rules often fire on legitimate application behavior, leading to alert fatigue and ongoing investment in security tools. Any application update or deployment introduces new behaviors, forcing teams into an endless loop of manual exclusions.



Kubescape, a CNCF Incubating project with over 10k GitHub stars, brings a new approach. After four years of helping DevOps and DevSecOps teams with Kubernetes configuration scanning and vulnerability monitoring, Kubescape now introduces a powerful new capability: eBPF-based runtime anomaly detection.



This new feature minimizes operational fatigue by automatically learning the normal behavior of workloads and alerting only on deviations. Instead of relying on static rules, Kubescape builds per-application behavioral baselines. It captures process execution, file access, network activity, Linux capabilities, and system calls. These baselines are stored as native Kubernetes objects that are portable, auditable, and reusable across environments, enabling scalable detection and deep observability.



In this Arsenal session, we'll showcase real-world examples of how Kubescape detects anomalies with minimal configuration, contrast it with rule-based tools, and demonstrate how it integrates into existing DevSecOps workflows. Attendees will walk away with a powerful, community-driven, open-source weapon in their cloud-native defense arsenal backed by a welcoming community and four years of trust in production environments.
</details>

<details>
  <summary>Capture the Train: Purple Team Edition!</summary>
  <p><span>Monitoring is often seen as a silver bullet for ICS security—but how effective is it really? In this Arsenal demo lab, you'll launch real attacks against an industrial setup composed of PLCs and SCADA controlling a model train and robotic arms. We'll assess which attacks are detected (or not!), leveraging two newly released plugins we developed to add more ICS capabilities to MITRE CALDERA: <a data-mce-href="https://github.com/wavestone-cdt/caldera-s7" href="https://github.com/wavestone-cdt/caldera-s7" style="outline: none;" data-mce-style="outline: none;">caldera-s7</a> and <a data-mce-href="https://url.us.m.mimecastprotect.com/s/nbcKCyP6mEt06v4NQcNt6uxz-L6?domain=urldefense.com" href="https://url.us.m.mimecastprotect.com/s/nbcKCyP6mEt06v4NQcNt6uxz-L6?domain=urldefense.com" style="outline: none;" data-mce-style="outline: none;">caldera-opcua.</a></span></p>
</details>

<details>
  <summary>Catch the Flow: Securing CI/CD Workflows with Flowlyt</summary>
  In March 2025, a significant supply chain attack compromised the widely-used GitHub Action `tj-actions/changed-files`, affecting over 23,000 repositories. Attackers injected malicious code that exfiltrated secrets from CI/CD runners by dumping them into workflow logs, exposing sensitive credentials like GitHub Personal Access Tokens and private RSA keys. This incident, assigned CVE-2025-30066, underscored the vulnerabilities inherent in relying on third-party actions within CI/CD pipelines.



In response to this breach, We developed "Flowlyt", a go langauge based static analysis tool designed to scan GitHub Actions workflows for malicious patterns, misconfigurations, and hardcoded secrets. Flowlyt integrates with Open Policy Agent (OPA) to enforce custom security policies, enabling organizations to proactively detect and mitigate potential threats in their CI/CD workflows.
</details>

<details>
  <summary>EMFIF2 - Electro Magnetic Fault Injection Fuzzing Framework</summary>
  In an era where embedded systems are increasingly integral to critical infrastructure, the need for robust hardware security has never been more paramount. However, conventional security testing methods often overlook physical attack vectors, particularly fault injection attacks. This presentation introduces EMFIF2, an advanced Electro Magnetic Fault Injection Fuzzing Framework designed to expose vulnerabilities in hardware through targeted electromagnetic pulse (EMP) attacks.

EMFIF2 leverages the precision of CNC machines combined with an EMP generator to automate fault injection, enabling researchers and engineers to conduct sophisticated hardware attacks with minimal manual intervention. The framework offers a modular and customizable approach to fuzzing, allowing users to script complex fault scenarios and observe device responses in real-time.

Through a series of case studies, this talk will demonstrate EMFIF2's effectiveness in uncovering flaws in popular embedded systems. We will discuss the framework's architecture, the integration of CNC and EMP technologies, and the challenges of replicating physical attack conditions in a controlled environment. Attendees will gain insights into setting up their own fault injection experiments and learn best practices for enhancing the security of hardware designs against such threats.

Whether you are a security researcher, embedded developer, or hardware enthusiast, EMFIF2 provides a powerful toolset for advancing your understanding of fault injection attacks and fortifying your hardware against them.

Keywords: Hardware Security, Embedded Security, Fault Injection, Electro Magnetic Fault Injection, Fuzzing, Secure Hardware Development Lifecycle
</details>

<details>
  <summary>GHARF: GitHub Actions RedTeam Framework</summary>
  In recent years, Red Team exercises have become increasingly important. However, the processes involved - such as developing attack scenarios, preparing tools, and building execution environments - require significant time and effort. These burdens have become major obstacles that limit both the frequency and quality of such exercises.



To address these challenges, we have developed a groundbreaking framework called GHARF, which applies the principles of Continuous Integration / Continuous Delivery (CI/CD) to Red Team operations, enabling more efficient execution of exercises.



By adapting CI/CD mechanisms—specifically the build and delivery pipelines - to Red Team workflows, GHARF automates various phases from the development and preparation of simulated attacks to their execution. This dramatically improves operational efficiency and enables faster iteration of attack cycles. We refer to this concept as Continuous Attack Integration / Continuous Attack Delivery, Deployment (CAI/CAD).



There are existing tools with similar capabilities, such as MITRE CALDERA and Atomic Red Team, which fall under the category of BAS (Breach and Attack Simulation). These tools aim to reduce the workload of Red Teams and support autonomous assessments by Blue Teams through attack automation. In contrast, GHARF is specifically designed to optimize the workflow of Red Teams themselves during active operations. Our approach focuses on streamlining the process so that Red Teams can pursue more advanced and realistic attack scenarios.



At this stage, GHARF is presented at a conceptual level due to ethical considerations. However, by introducing CAI/CAD through this announcement and sharing concrete examples, we hope to promote the adoption of this concept and contribute to the continued advancement of the Red Teaming field.
</details>

<details>
  <summary>MIPSEval: Multi-turn LLM Evaluation of LLM Safety</summary>
  Creating malicious and vulnerable code and harmful content has become easier with LLMs becoming publicly available. Even though the developers of cloud and most local LLMs are taking care to implement ethical guidelines and safety guardrails in their models, to make them refuse malicious content generation, malicious actors are still finding ways to elicit unwanted behaviors from LLMs. The malicious actors often use various jailbreaking or prompt injection techniques and their combination to achieve the desired result.



For this reason, it is important to constantly improve the safety of LLMs, both base models and applications using them. And in order to achieve better safety, we need to be able to evaluate LLMs thoroughly and constantly. The safety evaluation of LLMs should be easily runnable and automated as much as possible so that every change in the model or the LLM's system prompt can be evaluated quickly and precisely.



We present MIPSEval, a Multi-turn Injection Planning System for LLM Evaluation. It is a free-software LLM-based tool that uses genetic algorithms and reinforcement learning to evaluate the safety of LLMs against various jailbreaking/prompt injection techniques.



MIPSEval is the result of our experience as finalists in the Amazon Nova Trusted AI challenge.



Current human attacks against LLMs today do not rely on one prompt but include gradual attempts to elicit harmful behavior over multiple prompts in the conversation. The conversation can include jailbreaks combined with malicious as well as benign requests. MIPSEval uses LLM-guided genetic algorithms to evolve new multi-turn attack strategies, based on its previous attempts. MIPSEval has an internal multi-LLM agentic architecture to generate and execute attack strategies against the target LLM application that is being evaluated. 



To the best of our knowledge, MIPSEval is the first tool that uses multi-LLM agentic genetic-based architectures to design and automatically execute a conversation attack strategy. The strategies can be further updated by MIPSEval based on the ongoing conversation, meaning the steps not executed yet can be changed.



The MIPSEval tool was tested against cloud models from OpenAI and local models run via Ollama. It successfully generated strategies that elicit unsafe behavior from all the LLMs it was tested against.
</details>

<details>
  <summary>AnonyMask: Automated Masking and Unmasking of Explicit and Implicit Privacy Data</summary>
  AnonyMask is a privacy-preserving tool designed to automatically detect, mask, and unmask privacy data across various file formats. It allows enterprises to leverage the power of Large Language Model (LLM) or Retrieval-Augmented Generation (RAG) while ensuring that private or confidential information remains secure and compliant. With a single click, users can anonymize both explicit and implicit privacy data before sending it to LLM or RAG for analysis—and restore the original content afterward using smart unmasking. AnonyMask offers a secure, customizable, and offline-capable privacy-preserving document compatible with common file types such as .pdf, .docx, .xlsx, .csv, and .txt.
</details>

<details>
  <summary>Kubernetes Goat - A Hands-on Interactive Kubernetes Security Playground</summary>
  Containers are everywhere, and Kubernetes has become the de facto standard for deploying, managing, and scaling containerized workloads. Yet security issues continue to emerge in the wild daily, ranging from simple misconfigurations to sophisticated attacks. In this session, I'll introduce Kubernetes Goat, an interactive security playground designed to help you master the skills needed to hack and secure your Kubernetes clusters and container workloads.



Kubernetes Goat is an open-source platform featuring intentionally vulnerable scenarios within a Kubernetes cluster. From common vulnerabilities to notorious real-world attack patterns, each scenario is crafted to reflect actual security challenges - not theoretical simulations. Join me, the creator of Kubernetes Goat, as we dive deep into cluster vulnerabilities and emerge with practical defense strategies. Get ready to hack, learn, and shield your clusters!
</details>

<details>
  <summary>MBPTL - Most Basic Penetration Testing Lab</summary>
  The increasing threats to digital systems and online services demand more effective learning approaches in the field of cybersecurity, particularly in mastering penetration testing techniques. The Damn Vulnerable Web Application (DVWA) has long been used by beginners as a training platform but is limited to the application security domain, lacking coverage of key stages in the penetration testing process. This study proposes and evaluates the Most Basic Penetration Testing Lab (MBPTL), an open-source platform designed as a comprehensive learning environment for beginners to understand five essential phases of penetration testing: Reconnaissance, Vulnerability Analysis, Exploiting Vulnerable Apps, Password Cracking, and Post-Exploitation. Through a comparative study between MBPTL and DVWA, supported by direct experimentation involving five beginner participants, the findings indicate that MBPTL provides a more realistic, structured, and scenario-based learning experience. Moreover, MBPTL includes supporting documentation in the form of technical write-ups, enabling self-guided, step-by-step learning. The results contribute to the development of more holistic and applicable cybersecurity training methods and offer practical recommendations for educators and practitioners to adopt open laboratory-based approaches for building foundational information security skills. These findings also open opportunities for developing more adaptive and realistic penetration testing labs in the future.
</details>

<details>
  <summary>Project Foxhound</summary>
  <p>The web has seen a paradigm shift in recent years, from on-premise, monolithic server applications, to collections of cloud-based microservices. As such, much of the application logic has shifted from the server to the client, with program logic running on a user's browser. This shift has brought with it a new class of client-side web vulnerabilities, the most prominent being client-side (or DOM-based) cross-site scripting (XSS). Most state-of-the-art tools, however, are still focused on detection of their server-side counterparts (such as reflected XSS). Hunting for client-side issues, remains a manual effort, requiring time-intensive and costly penetration tests.

Project Foxhound is an innovative open-source tool for the detection of security and privacy issues in client-side (JavaScript) code. So far, it has been used to detect security vulnerabilities such as XSS, CRSF, request hijacking, markup injection, open redirects and memory corruption in WebAssembly, to name a few! In addition, Foxhound can be used to detect privacy violations such as browser fingerprinting, behavioural biometrics and perform comparitive privacy analysis.

Foxhound works by detecting potentially dangerous data-flows in the browser, using a technique known as dynamic taint tracking. Unlike other tools, Foxhound records detailed information about data manipulations, allowing filtering of sanitized flows and therefore reducing false positives. Foxhound can be seamlessly integrated into existing browser automation frameworks such as Playwright or Selenium, or used interactively to assist penetration tests. Foxhound is based on the popular Firefox web browser, and as such has a high compatibility with a small performance overhead.</p>
</details>

<details>
  <summary>PwnPad: A Hardware Hacking Learning Platform</summary>
  PwnPad is an open-source hardware training platform designed to teach embedded security through hands-on experimentation. Built to be affordable and fully reproducible, PwnPad enables users to learn real-world exploitation techniques using common protocols like UART, I2C, and SPI, along with fault injection and side-channel attacks.

PwnPad aims to lower the barrier to entry for hardware hacking by combining a low-cost design (buildable for under €20) with structured, gamified challenges that walk users through real attack scenarios step by step.

The platform includes all necessary design files, firmware, and documentation, allowing individuals or teams to assemble it independently. No prior experience with embedded hardware is required.
</details>

<details>
  <summary>TSURUGI LINUX: The Sharpest Weapon in Your DFIR Arsenal</summary>
  Any DFIR analyst knows that everyday in many companies, it doesn't matter the size, it's not easy to perform forensics investigations often due to lack of internal information (like mastery all IT architecture, have the logs or the right one...) and ready to use DFIR tools.



As DFIR professionals we have faced these problems many times and so we decided last year to create something that can help who will need the right tool in the "wrong time" (during a security incident).



And the answer is the Tsurugi Linux project that, of course, can be used also for educational purposes.

As usual a Tsurugi Linux special BLACKHAT EDITION will be released and shared with the participants.
</details>

<details>
  <summary>Minino: Multiband Hacking Now with GPS</summary>
  Minino is a Swiss Army knife for IoT hacking, designed to empower security professionals with a versatile, all-in-one toolkit for assessing and attacking IoT devices. Minino integrates WiFi, Bluetooth Low Energy (BLE), Zigbee, Thread, Matter, and a GPS module into a compact, open-source hardware solution. 



IoT security is often fragmented, requiring multiple tools to assess protocols and attack vectors. Minino simplifies this process by consolidating essential offensive security functions into a single device, making it an indispensable asset for penetration testers, red teamers, and hardware hackers.



With the latest update, Minino can upload your wardriving data straight into wiggle.net and wardrive for hours with its battery-saving mode.



This session will introduce real-world attack scenarios enabled by Minino, demonstrate its capabilities through live demos, and highlight its potential for uncovering new vulnerabilities. As an open-source project, it is built to evolve, with contributions from the security community driving continuous improvements.
</details>

<details>
  <summary>ThreatShield – The Intelligent Way of Threat Modelling</summary>
  <p>ThreatShield is an AI-powered threat modeling and security analysis tool designed to automate and elevate threat modeling using OpenAI's enterprise API. It processes raw documents like PRDs, architecture diagrams, confluence docs, slack threads and meeting transcripts to generate structured STRIDE-based threat models, attack trees, DREAD scoring, and mitigstions.</p>
</details>

<details>
  <summary>CVE2CAPEC - Convert CVEs to MITRE ATT&CK</summary>
  CVE2CAPEC is a free and open source MITRE ATT&amp;CK Navigator generator. Give it a list of CVEs, and it computes automatically all CWEs, CAPECs and MITRE ATT&amp;CK Techniques to draw the appropriate MITRE ATT&amp;CK matrix.
</details>

<details>
  <summary>DepConfuse: Shielding Your Packages from Dependency Confusion Attacks</summary>
  DepConfuse is a command-line tool that proactively detects dependency confusion vulnerabilities, a growing threat in modern software supply chains. By scanning SBOMs or PURLs, it identifies internal package names that are vulnerable to takeover in the public registry, allowing teams to remediate issues early in the development lifecycle.



Designed with an SBOM-first approach, DepConfuse scales across multi-language environments and integrates cleanly into CI/CD pipelines. Built on open standards like CycloneDX, it helps organisations adopt secure-by-default dependency practices and deploy effective supply chain defences at scale.
</details>

<details>
  <summary>Keep COM and Hijack On: Redefining Windows Session Hijacking</summary>
  While COM (Component Object Model) is a widely used and deeply integrated technology, its inherent complexity has left many intriguing areas largely underexplored for offensive security purposes. In this talk, I introduce a novel red team approach to abusing Windows COM objects for credential theft and session hijacking attacks.



Through my research, I identified new attack surfaces and primitives that leverage COM objects to execute unconventional "cross-session" attacks. These techniques achieve results similar to popular but heavily detected methods, such as dumping LSASS or remote process injections, while remaining stealthy. This approach enables red teamers to covertly compromise arbitrary Windows sessions and extract hashes remotely for password cracking or relay attacks.



By the end of the talk, attendees will gain a deep understanding of novel COM and DCOM attack surfaces, witness practical demonstrations of these techniques, acquire actionable offensive research strategies to discover similar techniques themselves, and gain access to proof-of-concept (PoC) tools that implement these methodologies, providing attendees a valuable resource for their future red team engagements.
</details>

<details>
  <summary>Patch Wednesday - Multi-Agent System for Patch Diffing</summary>
  Every month, Microsoft's Patch Tuesday drops dozens of security updates encapsulated in KBs, each addressing multiple CVEs across Windows components. PatchDiffAI is a first-of-its-kind, AI-driven multi-agent framework that ingests Patch Tuesday metadata, dissects each patched CVE, and delivers a fully automated, end-to-end root-cause analysis report.

By automating the most time-consuming steps of patch triage, PatchDiffAI empowers security teams to focus on mitigation and defense, rather than manual analysis overhead.

We'll share our journey in building this AI-driven vulnerability analysis tool, highlighting the key challenges we faced and how we overcame them, ultimately achieving 86% accuracy in root-cause labeling of Patch Tuesday reports.

Attendees will gain insights into designing and coordinating multiple specialized AI agents, each with distinct roles and models, working together seamlessly - from natural language processing of vendor advisories to byte-level binary diffing.
</details>

<details>
  <summary>ROP ROCKET: Advanced ROP Automation for Exploitation</summary>
  ROP ROCKET is a groundbreaking, next-generation tool specifically designed for Return-Oriented Programming (ROP), boasting unparalleled capabilities. This tool introduces several innovative techniques, including a novel approach to invoking Heaven's Gate via ROP, seamlessly transitioning from x86 to x64 architectures, and invoking Windows syscalls directly via ROP to evade Data Execution Prevention (DEP), thus eliminating the reliance on less stealthy Windows API functions.



The focal point of this tool is automatic ROP chain generation—constructing complete ROP exploits. The tool introduces several groundbreaking ROP techniques, including both x86 and x64 Heaven's Gate and using Windows syscalls to bypass DEP. To overcome DEP, we automate chain generation for Windows syscalls NtAllocateVirtualMemory and NtProtectVirtualMemory. In addition, ROP ROCKET can avoid the need to bypass DEP by instead chaining multiple APIs together to achieve functionality more equivalent to traditional shellcode.



For Black Hat Europe Arsenal 2025, we are proud to support for building ROP chains for many new WinAPIs: WinExec, DeleteFileA, CreateToolhelp32Snapshot, URLDownloadToFileA, OpenProcess, Process32First, Process32Next, RegSetKeyValueA, RegCreateKeyA, WriteProcessMemory, HeapCreate, OpenSCManagerA, CreateServiceA, ShellExecuteA, CreateRemoteThread, VirtualAllocEx, TerminateProcess, CreateProcessA, HeapAlloc, and HeapCreate, among others. These APIs can be targeted using ROP chains generated automatically via patterns with PUSHAD or through more advanced combination involving PUSHAD coupled with MOV dereferences. 



One of the features of ROP ROCKET is the sheer diversity of possibilities it unlocks in ROP chain construction, allowing unique and unusual combinations that traditionally might not be achievable by ROP chain automation. The tool uses extensive emulation to evaluate the fitness of individual ROP gadgets, allowing unusual or longer ROP gadgets to be used. It also builds, emulates, and debugs parts of some ROP chains internally to solve certain problems, allowing for ROP chains to be built with the mov dereference or sniper approach, rather than relying simply on the PUSHAD approach. When needed, ROP ROCKET dynamically calculates and adjusts distances to function parameters through emulation, ensuring optimal chain performance.



Despite the complexity traditionally associated with ROP, ROP ROCKET empowers users with advanced yet accessible capabilities.  The number of supported patterns for different WinAPI's and syscalls far surpasses the capabilities of prior ROP generation tools, making this tool essential for real-world ROP development on the Windows platform.
</details>

<details>
  <summary>The Only 'Kanvas' You Need When Responding to Security Incidents.</summary>
  <div>KANVAS is an open-source IR (Incident Response) case management tool with an intuitive desktop interface, built using Python. It provides a unified workspace for investigators working with SOD (Spreadsheet of Doom) or similar spreadsheets, enabling key workflows to be completed without switching between multiple applications. Kanvas supports many external lookups, making it easier to add context during investigations.

Some of the notable features include:

1. Built on the SOD (Spreadsheet of Doom): All data remains within the spreadsheet, making distribution and collaboration simple—even outside the application.
2. Attack Chain Visualization: Visualizes lateral movement for quick review of the adversary's attack path. Re-draw options allow the diagram to be displayed in multiple ways.
3. Incident Timeline: Presents the incident timeline in chronological order, helping investigators quickly understand the sequence and timing of events.
4. MITRE ATT&amp;CK Mapping: Provides up-to-date MITRE tactics and techniques for mapping adversary activities.
5. MITRE D3FEND Mapping: Helps map defense strategies based on identified ATT&amp;CK techniques. This is especially useful when responding to incidents from a defender's perspective.
6. VERIS Reporting: Offers an interface to track VERIS data, which can be shared post-incident with government entities and contribute to the Verizon Data Breach Investigations Report.
7. Markdown Editor: Provides an interface to create and update Markdown documents—ideal for note-taking or loading investigative playbooks.
8. STIX Export: Exports IOCs (Indicators of Compromise) in STIX 2.1 format, which can be easily imported into OpenCTI or MISP platforms.
9. Ransomware Victim Check: Verifies if a customer's or organization's data has been published online following a ransomware attack.
10. Bookmarks: Offers a curated list of security tools, an up-to-date list of Microsoft portal URLs, and the ability to create custom investigation-specific bookmarks.
11. Entra ID Reference: Provides a searchable list of known and malicious Microsoft Entra ID AppIDs—useful for investigating Business Email Compromise (BEC) cases.

Useful for:

1. Forensic Investigators
2. Incident Responders
3. Threat Hunters
4. SOC Analysts</div>
</details>

<details>
  <summary>Breaking the Tunnel: Real-Time API Interception in MDM-Locked Mobile Apps with KnoxSpy</summary>
  Mobile Device Management (MDM) applications, while crucial for organizational control, present a significant challenge for security professionals seeking to conduct thorough API testing. The enforced routing of all application traffic through centrally managed VPNs renders conventional interception proxies and system-level techniques ineffective. This limitation creates a critical gap in the security assessment of these privileged applications.



Introducing KnoxSpy, a novel tool developed to address this challenge. By employing dynamic instrumentation via Frida, KnoxSpy intercepts network traffic directly within the target MDM application. This is achieved by hooking into the application's network libraries at runtime. KnoxSpy captures requests before they are routed through the MDM's VPN and responses after they emerge from it. KnoxSpy facilitates real-time analysis and modification of API traffic, thereby enabling comprehensive security testing without disrupting the MDM-enforced tunnel. Modified requests can be seamlessly reinjected using the application's own network libraries.



KnoxSpy has been successfully utilized in the security assessment of numerous MDM applications for prominent organizations, leading to the discovery of critical vulnerabilities. This tool empowers security teams to enhance the security posture of MDM-managed environments. A live demonstration of KnoxSpy will be presented.
</details>

<details>
  <summary>EKSi Lite: Simple lightweight EKS Cluster Listing & Security Tool</summary>
  EKSi is a lightweight command line python tool designed for quick enumeration and listing of Kubernetes resources within Amazon EKS context, showing the relationships between AWS services and Kubernetes components during internal security audits. During internal security reviews and operational assessments, security professionals often need to quickly gather information about EKS cluster components without navigating through the AWS console or multiple kubectl commands. EKSi solves this problem by providing a cli for extracting and listing components within EKS and Kubernetes context.



The tool acts as a basic data collection and enumeration utility that presents Kubernetes resources, their AWS associations, and security relevant configurations in the table format in the terminal. This makes it invaluable for security professionals who need to quickly understand the attack surface of an EKS cluster without requiring direct console access.





Key capabilities include:

- Simple resource enumeration: List AWS nodes, services, pods, persistent volumes, and storage classes with a single command including cluster summary.

- AWS IAM integration mapping: Display AWS IAM roles and IAM permissions associated with service accounts and pods

RBAC.

- Security configuration display: Present security contexts, volume mounts, and container configurations

- Image inventory: List all container images running in the cluster along with finding list of unique images running in cluster

- Image secret detection: Identify exposed secrets in container images running in the cluster using trufflehog.

- Flexible cluster scope: This tool can be used to get the EKS context  cluster wide as well as namespace scope.
</details>

<details>
  <summary>Nightingale: Docker for Pentesters</summary>
  Nightingale is an innovative open-source tool designed to simplify and streamline the process of penetration testing. Addressing the complexities and time-consuming setup required for effective vulnerability assessments, Nightingale leverages Docker to provide a consistent, repeatable, and resource-efficient testing environment. This tool eliminates the need for multiple installations, making it easier for organizations to identify and address security vulnerabilities.

Existing penetration testing tools often require extensive setup and configuration, which can be a barrier to effective security testing. Tools like nmap, gau, amass and Metasploit provide powerful features but lack the seamless integration and ease of use, which is offered by Nightingale. By using Docker, Nightingale ensures a more consistent and portable environment, addressing the limitations of other tools and enhancing efficiency and effectiveness in penetration testing.

Nightingale is built on Docker, which allows for the creation of isolated and consistent environments. The design focuses on ease of use and resource optimization, incorporating pre-installed tools and frameworks necessary for comprehensive vulnerability assessments. The development process involved extensive testing and refinement to ensure compatibility and performance across different platforms.
</details>

<details>
  <summary>Pygraphistry</summary>
  PyGraphistry is a GPU-accelerated Python library that makes it easy to analyze and visualize large-scale graphs—ideal for uncovering complex patterns in cybersecurity, threat hunting, and fraud detection. It combines rich interactive visualizations with dataframe-native graph querying, ML workflows, and seamless integration into existing Python, web, and notebook environments. With support for tools like Pandas, cuDF, and NetworkX, PyGraphistry helps security professionals go from raw data to insight faster—without needing deep expertise in graph theory or infrastructure.
</details>

<details>
  <summary>Raising BloodHound Attack Paths to Life</summary>
  Security practitioners rely heavily on lab environments to test tools, techniques, and exploits before bringing them into live environments. But most labs are built with generic setups, such as one domain and a couple of workstations, and rarely capture the tangled complexity of real-world Active Directory: multiple domains, nested groups, delegated permissions, misconfigured ACLs, and privilege escalation paths that only exist through deep object relationships.



Recreating these environments manually is tedious, time-consuming, and doesn't scale. Because of this, red teamers often end up testing directly in production or relying on incomplete assumptions, while defenders may be hesitant to perform testing or hardening out of concern for causing outages or disrupting critical systems.



This demo introduces LudusHound. LudusHound bridges a long-standing gap in red and blue team operations: the ability to recreate real-world Active Directory environments with realistic misconfigurations and relationships based on actual production data. While tools exist to analyze environments (like BloodHound), there has never been a streamlined way to take that data and automatically reconstruct a functional lab environment for testing or training. Why? Because it's hard.



I'll walk through how it works, show real-world use cases, and release the tool publicly. Whether you're red, blue, purple, or just learning, you'll walk away with a practical method for replicating the exact AD conditions of the organization you are attacking, or defending.
</details>

<details>
  <summary>SBoM Play</summary>
  SBOMPlay is a browser-first, privacy-aware SBOM visualization and enrichment tool designed to showcase the real potential of SBOMs beyond just vulnerability tracking.



Instead of relying on server-side infrastructure or custom scripts, SBOMPlay runs entirely in the browser. It enables users to extract SBOMs from GitHub repositories, enrich them with data from osv.dev, and analyze dependencies across repositories and organizations in a unified view.



Whether it's reducing tech debt, surfacing redundant packages, or evaluating license compliance, SBOMPlay makes software inventory exploration accessible to developers, security engineers, and decision-makers alike.



The tool is actively developed, and the latest features will be demonstrated live during the session.
</details>

<details>
  <summary>Models as Malware: Attacking and Defending the AI Supply Chain</summary>
  The open source model development community is growing exponentially, with over 1.8 million publicly accessible models on HuggingFace today.



Institutions and individuals alike leverage this platform to access and share state-of-the-art AI for deployment on a wide range of infrastructure, from personal devices to production systems.



Under the hood, many AI model formats are both data (weights) and code (architecture), with most users relying on easy but vulnerable serialization formats to distribute models — and attackers are taking notice, embedding payloads in models to connect to C2 servers:

- https://thehackernews.com/2025/02/malicious-ml-models-found-on-hugging.html (Feb 2025)

- https://arstechnica.com/security/2024/03/hugging-face-the-github-of-ai-hosted-code-that-backdoored-user-devices/ (Mar 2024)



In this session, you'll learn 1) how to instrument and detect malicious payloads in AI models and 2) how recent enhancements to ClamAV are protecting customers from supply chain compromises in the era of AI.



Working understanding of Python programming is expected.
</details>

<details>
  <summary>WHIDBOARD: Plug It In, Set It Up & Get Ready to Hack!</summary>
  WHIDBOARD is the ultimate tool-suite for Hardware Hackers. It is designed to act as the perfect Swiss-Army-Knife for hacking any (I)IoT &amp; Embedded devices. Thanks to its core controller (a.k.a. BRUSCHETTAPRO) it can support the interaction with multiple protocols (i.e. UART, SPI, I2C, JTAG &amp; SWD) as well as different Logic Levels (i.e. 1.8V, 2.5V, 3.3V and the VREF of the target itself). Nonetheless, it also allows the hacker to enumerate (UART, JTAG &amp; SWD) thanks to its 24 channels' Pin Enumerator feature, as well as the ability to act as a 8 channels Logic Analyzer at 24MHz.
</details>

<details>
  <summary>DICE: Device Identification and Classification Engine</summary>
  In recent years, the Internet has experienced a significant surge in connected devices, with an ever-growing number of sensors and monitoring systems—spanning industries and domestic networks—now exposed to the Internet and reliant on our ability to keep them secure (e.g., in healthcare, home automation, and manufacturing). However, securing Internet-facing devices is no trivial task. Applying patches, firewall rules, and strong credentials are only small steps during their security life-cycle. Since these steps work in tandem, failing even a few can significantly increase the risk of compromise. The cybersecurity community continues to build on its efforts to mitigate this issue from many fronts, all while investigating society's new challenges with technology and their security implications. 



We present {DICE}, a modular Device Identification and Classification Engine to detect vulnerabilities on Internet-facing devices. DICE is an engine that orchestrates network measurements and assists in most phases of vulnerability assessments. It was initially conceived as a tool for Internet surveys and network monitoring, a far broader scope than single-host scanning. However, DICE can be used at many different levels. Its main purpose is to provide flexibility for as many measurements as you can think of.
</details>

<details>
  <summary>KubeShadow - Advanced Offensive Kubernetes Red-Team Framework</summary>
  KubeShadow is an advanced red team and adversary simulation framework purpose-built to exploit, persist, and operate within Kubernetes clusters in stealth. Far beyond traditional misconfiguration scanners, KubeShadow delivers real-world offensive capabilities designed to emulate high-caliber threat actors operating across AWS EKS, GCP GKE, and Azure AKS managed clusters.



Crafted in Go for high performance and raw control over API interactions, KubeShadow enables attackers and defenders alike to understand the true breach impact of overlooked Kubernetes controls — not just whether they conform to best practices. This tool directly interacts with the Kubernetes control plane, etcd datastore, and kubelet APIs, offering a modular attack surface that provides deep access, stealth-focused exploitation, and evasive privilege escalation techniques. Each module is engineered for silent operation, bypassing modern runtime detection (EDRs, Falco, CSPMs), allowing for long-lived access and high-fidelity simulation.



KubeShadow enables host-networked pod insertion via direct etcd manipulation to bypass RBAC, network policies, and admission controllers; performs stealth recon and cluster fingerprinting with cloud-aware profiling (AWS, GCP, Azure); hijacks cloud metadata endpoints for identity pivoting and lateral movement; embeds backdoors into container images for stealth supply chain poisoning; and establishes long-term persistence via raw etcd-level control plane tampering. As part of its future roadmap, KubeShadow aims to integrate an AI-assisted decision engine to dynamically construct optimal attack paths using machine learning — enabling automated kill chain chaining from reconnaissance to post-exploitation in adaptive, context-aware workflows.



KubeShadow is a stealth-first, offensive-driven, and operator-focused framework engineered to simulate real-world adversaries operating in Kubernetes environments. It enables execution of modern Kubernetes kill chains — from initial access to post-exploitation — with minimal footprint and maximum impact, offering perspectives beyond traditional security assessments.
</details>

<details>
  <summary>Red AI Range (RAR)</summary>
  Red AI Range (RAR) is a comprehensive security platform designed specifically for AI red teaming and vulnerability assessment. It creates realistic environments where security professionals can systematically discover, analyze, and mitigate AI vulnerabilities through controlled testing scenarios.



As organizations increasingly integrate AI systems into critical infrastructure, the need for robust security testing has become essential. RAR addresses this need by providing a standardized framework that consolidates various AI vulnerabilities in one accessible environment for both academic research and industrial security operations.



Red AI Range enables security professionals to systematically assess and exploit vulnerabilities within AI systems through realistic, controlled attack scenarios. The platform's advanced Docker-based architecture resolves complex dependency issues inherent in AI frameworks, providing isolation, rapid environment resets, parallel testing capabilities, and simplified deployments. An intuitive management system streamlines deployment of vulnerable AI systems and security toolkits, offering straightforward controls via a user-friendly interface.



With remote agent support, teams can securely leverage distributed resources such as GPU-equipped clusters, coordinate across multiple locations, and manage testing scenarios from a centralized interface. Built-in session recording ensures comprehensive documentation, facilitates knowledge transfer, and supports stakeholder demonstrations. Suitable for corporate security teams, researchers, and educators, RedAIRange is ideal for vulnerability validation, exploration of emerging AI threats, practical skill development, and reproducible security research.
</details>

<details>
  <summary>Securing Secrets from Dev Machine to Deployments Using SLV</summary>
  SLV (Secure Local Vault) bridges the gap between local developer environments and secure CI/CD pipelines by offering a lightweight, CLI-first tool for managing secrets without relying on centralized, cloud-hosted secrets managers. This talk will demonstrate how sensitive credentials can leak across development to production workflows and how SLV prevents this through isolated, encrypted vaults, ephemeral secrets injection, and audit-friendly flows. With real-world attack paths as context, we will show how SLV hardens secrets handling from the first line of code to final deployment.
</details>

<details>
  <summary>SkyEye: When Your Vision Reaches Beyond IAM Boundary Scope in the Cloud</summary>
  Modern cloud environments demand a comprehensive understanding of IAM configurations across users, roles, groups, and the intricate web of inline and managed policies. Yet, as organizations scale their use of cloud technologies, the act of enumerating effective permissions and resource authorizations remains fraught with blind spots, especially when relying on traditional principal-specific enumeration tools and frameworks. When a single set of credentials lacks the necessary permissions, or when multiple principals operate in isolation, cloud penetration testers are left with an incomplete and fragmented IAM landscape, resulting in hidden privilege escalation vectors, undetected misconfigurations, and weakened compliance postures.



However, is a principal-centric enumeration strategy sufficient for reconnaissance in adversary simulation or defense? Our research suggests not. The inability to correlate and chain disparate IAM permissions across multiple principals leads to critical false negatives and gaps in situational awareness - the gaps that threat actors are increasingly adept at exploiting.



In this Arsenal session, we will showcase a new framework: SkyEye - The First Cooperative Multi-Principal IAM Enumeration Framework for AWS Cloud. SkyEye Framework proposed and developed two novel models: the Cross-Principal IAM Enumeration Model (CPIEM) and the Transitive Cross-Role Enumeration Model (TCREM). Unlike conventional tools and frameworks, SkyEye is able to synchronize reconnaissance across multiple user and role sessions, dynamically chaining and merging their vantage points to unravel the full spectrum of permissions, resource authorizations, and hidden escalation paths. This methodology exposes not only what each principal can see, but also what they can achieve in combination, surfacing privilege chains and attack paths invisible to siloed IAM enumeration.



SkyEye is further powered by an extensible dataset mapping AWS actions to MITRE ATT&amp;CK Cloud - TTPs, alongside with severity ratings, adversarial abuse methodologies, and real-world threat actor behaviors. This enables immediate translation of raw IAM data into valuable information for red teaming and cloud defense.



Join us to see how SkyEye sets a new standard for cloud reconnaissance to improve cloud adversary simulation and detection engineering. Witness how cooperative multi-principal IAM enumeration can transform your reconnaissance of AWS permissions, and why a truly complete IAM picture is only viable when principals cooperate together.
</details>

<details>
  <summary>Tanto 2.0</summary>
  Tanto 2.0: an open-source, binary analysis, slicing framework and plugin for Binary Ninja designed to help discover and verify bugs and vulnerabilities faster than ever before. As government-funded programs and private-sector research continue to encounter increasingly complex problems that require more data and context to solve, slicing aims to cut those problems back down to size.



Tanto lets you:

* Explore how slicing can be used on any target, regardless of architecture, to reduce the context required for manual, automatic, and machine-learning based solutions.

* Demonstrate slicing to verify reachability and exploitability of bugs in real-world targets.

* Identify and filter points of interest using slices.

* Use slicing to assist with recovering program semantics.

* Perform fine-grained dataflow queries, both intra-procedural and inter-procedural, through slicing.

* Discuss how to apply these same concepts to recover modules and interfaces in and among binaries.

* Provide a launchpad for researchers and developers to experiment with novel slices of their own.



Researchers are already using Tanto for vulnerability research, malware analysis, modeling their own program patterns and behaviors, performing obfuscation research on globally flattened interprocedural control flow, and so much more!
</details>

<details>
  <summary>DepConfuse: Shielding Your Packages from Dependency Confusion Attacks</summary>
  DepConfuse is a command-line tool that proactively detects dependency confusion vulnerabilities, a growing threat in modern software supply chains. By scanning SBOMs or PURLs, it identifies internal package names that are vulnerable to takeover in the public registry, allowing teams to remediate issues early in the development lifecycle.



Designed with an SBOM-first approach, DepConfuse scales across multi-language environments and integrates cleanly into CI/CD pipelines. Built on open standards like CycloneDX, it helps organisations adopt secure-by-default dependency practices and deploy effective supply chain defences at scale.
</details>

<details>
  <summary>EntraGoat - A Deliberately Vulnerable Entra ID Environment</summary>
  EntraGoat is a deliberately vulnerable environment designed to simulate real-world security misconfigurations and attack scenarios in Microsoft Entra ID (formerly Azure Active Directory). Security professionals, researchers, and red teamers can leverage EntraGoat to gain hands-on experience identifying and exploiting identity and access management (IAM) vulnerabilities, privilege escalation paths, and other security flaws specific to cloud-based Entra ID environments.
</details>

<details>
  <summary>IOCTL-hammer - Parameter centric IOCTL Fuzzer for Windows Drivers</summary>
  IOCTL-hammer is a lightweight, Python-based fuzzing harness designed for efficient and targeted security auditing of Windows driver IOCTL interfaces. This tool addresses the high barrier to entry for kernel driver testing by providing a simple, accessible framework that focuses on the most common vulnerability patterns: buffer mismanagement. Rather than relying on complex, coverage-guided instrumentation, ioctl-hammer adopts a parameter-centric methodology, systematically manipulating the four core user-mode buffer descriptors sent via DeviceIoControl.

The fuzzer executes a structured, predefined suite of test cases designed to stress boundary conditions, null parameter handling, and size discrepancies. Despite its simplicity, this focused approach has proven highly effective in real-world testing against proprietary Windows drivers, successfully uncovering multiple zero-day vulnerabilities including a kernel-to-user heap overflow, Denial of Service vulnerabilities and Direct BSODs.  IOCTL-hammer is designed for security engineers and researchers to quickly perform initial vulnerability assessments on IOCTLs, find low-hanging fruit, and validate findings without requiring extensive setup or kernel debugging expertise for initial discovery.
</details>

<details>
  <summary>MBPTL - Most Basic Penetration Testing Lab</summary>
  The increasing threats to digital systems and online services demand more effective learning approaches in the field of cybersecurity, particularly in mastering penetration testing techniques. The Damn Vulnerable Web Application (DVWA) has long been used by beginners as a training platform but is limited to the application security domain, lacking coverage of key stages in the penetration testing process. This study proposes and evaluates the Most Basic Penetration Testing Lab (MBPTL), an open-source platform designed as a comprehensive learning environment for beginners to understand five essential phases of penetration testing: Reconnaissance, Vulnerability Analysis, Exploiting Vulnerable Apps, Password Cracking, and Post-Exploitation. Through a comparative study between MBPTL and DVWA, supported by direct experimentation involving five beginner participants, the findings indicate that MBPTL provides a more realistic, structured, and scenario-based learning experience. Moreover, MBPTL includes supporting documentation in the form of technical write-ups, enabling self-guided, step-by-step learning. The results contribute to the development of more holistic and applicable cybersecurity training methods and offer practical recommendations for educators and practitioners to adopt open laboratory-based approaches for building foundational information security skills. These findings also open opportunities for developing more adaptive and realistic penetration testing labs in the future.
</details>

<details>
  <summary>Minino: Multiband Hacking Now with GPS</summary>
  Minino is a Swiss Army knife for IoT hacking, designed to empower security professionals with a versatile, all-in-one toolkit for assessing and attacking IoT devices. Minino integrates WiFi, Bluetooth Low Energy (BLE), Zigbee, Thread, Matter, and a GPS module into a compact, open-source hardware solution. 



IoT security is often fragmented, requiring multiple tools to assess protocols and attack vectors. Minino simplifies this process by consolidating essential offensive security functions into a single device, making it an indispensable asset for penetration testers, red teamers, and hardware hackers.



With the latest update, Minino can upload your wardriving data straight into wiggle.net and wardrive for hours with its battery-saving mode.



This session will introduce real-world attack scenarios enabled by Minino, demonstrate its capabilities through live demos, and highlight its potential for uncovering new vulnerabilities. As an open-source project, it is built to evolve, with contributions from the security community driving continuous improvements.
</details>

<details>
  <summary>Spikee: Simple Prompt Injection Kit for Evaluation and Exploitation</summary>
  Spikee (https://spikee.ai) is an open-source tool we developed from two years of security assessments of LLM applications and GenAI use cases, focusing on practical cyber security risks. These risks stem from the interaction between LLMs and the applications that rely on them, leading to exploitable outcomes such as data exfiltration, XSS, and resource exhaustion—rather than generating harmful content, as seen in typical "LLM red teaming". Unlike academic approaches that can be impractical in the field and often give difficult to interpret, generic results, Spikee gives pentesters the tools to actually test LLM apps with customizable datasets and attacks that match a specific application's constraints and use-cases. Built from our hands-on experience, Spikee addresses prompt injection risks across the entire LLM application pipeline, featuring evasion plugins and dynamic attacks specifically designed to bypass model alignment and state-of-the-art prompt injection filters.
</details>

<details>
  <summary>SQL Data Guard: Enforcing Safe LLM-to-Database Interactions via Inline or MCP Deployment</summary>
  SQL Data Guard, introduced at Black Hat Asia 2025, protects against insecure SQL by validating and rewriting queries to enforce access restrictions and block injection payloads. As LLMs increasingly generate SQL dynamically, we extend sql-data-guard with a containerized application that secures MCP-based systems. It intercepts queries, applies schema-aware policies, and ensures only safe, compliant SQL reaches internal database services—adding a crucial protection layer for AI-driven environments.
</details>

<details>
  <summary>ThreatShield – The Intelligent Way of Threat Modelling,</summary>
  <p>ThreatShield is an AI-powered threat modeling and security analysis tool designed to automate and elevate threat modeling using OpenAI's enterprise API. It processes raw documents like PRDs, architecture diagrams, confluence docs, slack threads and meeting transcripts to generate structured STRIDE-based threat models, attack trees, DREAD scoring, and mitigstions.</p>
</details>

<details>
  <summary>Blackdagger: Cyber Workflow Automation Framework</summary>
  Blackdagger is an innovative workflow automation framework specifically designed to simplify and accelerate cybersecurity operations across DevOps, DevSecOps, MLOps, MLSecOps, and Continuous Automated Red Teaming (CART). At its core, Blackdagger reduces complexity and manual overhead by leveraging a novel declarative YAML-based Directed Acyclic Graph (DAG) approach, enabling users to intuitively define automation pipelines, clearly visualize task dependencies, and minimize extensive scripting or coding typically required by traditional cronbased schedulers and orchestration platforms. A user-friendly built-in Web UI further empowers users by providing easy, real-time management, monitoring, and execution of workflows. 



Blackdagger's ecosystem includes several integrated tools and workflow suites, creating a comprehensive cybersecurity automation framework: 

- Blackcart: A specialized Docker container optimized for Continuous Automated Red Teaming (CART) and DevSecOps pipeline tasks. 

- Blackdagger YAMLs: Pre-tested example workflows, demonstrating real-world DevSecOps and CART use-cases, facilitating quick adoption and adaptation. 

- Blackdagger Github Infra: A suite of advanced workflows utilizing GitHub Actions infrastructure for enhanced defense evasion techniques, scalability, and performance. 

- Blackdagger Web Kit (BWK): A browser extension integrating all core functionalities, enabling direct interaction and execution of Blackdagger workflows from within the browser. 



During this Arsenal session, attendees will see practical demonstrations of Blackdagger's capabilities, including rapid deployment of DevSecOps and CART workflows, pipeline visualization, and streamlined security task automation in action.
</details>

<details>
  <summary>Cloud Sec AI BOT</summary>
  <p>Are you worried about finding the right set of commands to identify security misconfigurations in your cloud subscriptions? Stop wrestling with AWS CLI, Azure CLI, and gcloud syntax - just ask in plain English.

AI-powered multi-cloud security assistant that turns plain English into validated cloud commands through a secure MCP server with read-only permissions across your entire cloud estate.

<span>One interface. All your clouds: Ask any question to the BOT regarding any security misconfiguration and receive consolidated results from AWS, Azure, and Google Cloud without mastering different CLI syntaxes. Cloud Sec AI Bot helps security engineers of multiple flavors validating any cloud misconfiguration such as exposed public storage, missing MFA configurations, excessive role permissions, and least-privilege policy violations across your entire cloud infrastructure.</span>
</p>
</details>

<details>
  <summary>DNSBomb Toolkit: Evaluating New Powerful-Ever Pulsing DoS Attacks</summary>
  DNSBomb Toolkit is the first public toolset for evaluating, reproducing, and defending against a new class of pulsing DoS attacks that exploit widely deployed DNS mechanisms. Based on our IEEE S&amp;P 2024 paper, the toolkit enables controlled experiments of DNS query accumulation, amplification, and pulsing via timeout abuse, query aggregation, and fast-returning mechanisms. We provide both attack simulation and detection modules to empower researchers, vendors, and defenders to test and patch vulnerable DNS software or configurations. DNSBomb Toolkit has already contributed to over 10 CVE disclosures and security patches across major DNS vendors, including BIND, Unbound, PowerDNS, and Knot.



The paper abstract is listed below:



DNSBomb is a new practical and powerful pulsing DoS attack exploiting DNS queries and responses with an amplification factor above 20,000x.



DNS employs a variety of mechanisms to guarantee availability, protect security, and enhance reliability. In this paper, however, we reveal that these inherent beneficial mechanisms, including timeout, query aggregation, and response fast-returning, can be transformed into malicious attack vectors. We propose a new practical and powerful pulsing DoS attack, dubbed the DNSBomb attack. DNSBomb exploits multiple widely-implemented DNS mechanisms to accumulate DNS queries that are sent at a low rate, amplify queries into large-sized responses, and concentrate all DNS responses into a short, high-volume periodic pulsing burst to simultaneously overwhelm target systems. Through an extensive evaluation on 10 mainstream DNS software, 46 public DNS services, and around 1.8M open DNS resolvers, we demonstrate all DNS resolvers could be exploited to conduct more practical-and-powerful DNSBomb attacks than previous pulsing DoS attacks. Small-scale experiments show the peak pulse magnitude can approach 8.7Gb/s and the bandwidth amplification factor could exceed 20,000x. Our controlled attacks cause complete packet loss or service degradation on both stateless and stateful connections (TCP, UDP, and QUIC). In addition, we present effective mitigation solutions with detailed evaluations. We have responsibly reported our findings to all affected vendors, and received acknowledgement from 24 of them, which are patching their software using our solutions, such as BIND, Unbound, PowerDNS, and Knot. 10 CVE-IDs are assigned.



We concluded that ANY SYSTEM or MECHANISM, which can aggregate "things", could be exploited to construct the pulsing DoS traffic, such as DNS and CDN.



Please review https://dnsbomb.net/ for details and the full CVE list.
</details>

<details>
  <summary>From Triage to Threat Modeling: Open-Source Security LLM in Action</summary>
  Security teams are drowning in alert noise, manual triage, and time-consuming reviews, while attackers are moving with speed and precision. This demo introduces an open-source, instruction-tuned Large Language Model (LLM), purpose-built to assist security practitioners across both SOC and Offensive Security workflows. 



Unlike generic chat models, this LLM is trained on real analyst tasks and security-native language. It helps SOC teams summarize alerts, map MITRE TTPs, trace attack paths, and draft incident reports; freeing up time for deeper investigation. Offensive teams use it to generate red-team test plans, model threats, and surface remediation guidance directly from pull requests. 



What sets this project apart isn't the model, but the ecosystem around it. Alongside the LLM, we're releasing a Security LLM Cookbook. This is a hands-on guide with prompt templates, code snippets, lightweight RAG pipelines, and deployment examples for SIEMs, Cloud Environments, and beyond. Everything is open-source, transparent, and customizable, giving you the freedom to adapt the model to your own environment, tooling, and threat landscape. 



This Arsenal demo is designed to be practical, interactive, and immediately useful. Whether you're building internal copilots, exploring AI-native defense workflows, or just curious how LLMs can augment your team, you'll walk away with a working toolkit and a model you can trust.
</details>

<details>
  <summary>Golden dMSA: One Key to Rule Them All</summary>
  Golden dMSA is a post-exploitation and privilege escalation tool that exploits vulnerabilities in Managed Service Accounts (MSAs) within Active Directory forests. This attack enables adversaries to obtain Kerberos tickets and derive passwords for all domain-managed service accounts (dMSAs) and group-managed service accounts (gMSAs) across the forest by temporarily compromising a single domain.

Domain-managed service accounts are designed as enhanced MSAs with strengthened security controls. By design, non-privileged users should lack the permissions to enumerate these protected accounts. However, this attack method bypasses these restrictions, allowing unauthorized enumeration of dMSA and gMSA accounts from standard user privileges. Once an attacker gains control of any domain within the forest, they can leverage extracted cryptographic material and domain-specific data to algorithmically predict and reconstruct the passwords of all managed service accounts, effectively compromising the entire forest's service account infrastructure.
</details>

<details>
  <summary>Spotter – Universal Kubernetes Security Engine</summary>
  Spotter is a groundbreaking open-source tool or solution designed to secure Kubernetes clusters throughout their lifecycle. Built on the native tooling of Kubernetes by leveraging CEL (Common Expression Language) for policy definitions, we can define unified security scanning across development, CLI, CI/CD, Admission Controllers, deployments, runtime, and continuous monitoring. Its unique approach enables both enforcement and monitoring modes, ensuring that policies can be applied consistently and mapped directly to industry standards such as CIS, MITRE ATT&amp;CK, etc.



Spotter provides extreamly high flexbility across all Kubernetes phases, providing an innovative approach that no other open-source or commercial solution can replicate. It seamlessly bridges security, DevOps, and platform teams, effectively solving the real-world challenges faced by day-to-day operations.
</details>

<details>
  <summary>Models as Malware: Attacking and Defending the AI Supply Chain</summary>
  The open source model development community is growing exponentially, with over 1.8 million publicly accessible models on HuggingFace today.



Institutions and individuals alike leverage this platform to access and share state-of-the-art AI for deployment on a wide range of infrastructure, from personal devices to production systems.



Under the hood, many AI model formats are both data (weights) and code (architecture), with most users relying on easy but vulnerable serialization formats to distribute models — and attackers are taking notice, embedding payloads in models to connect to C2 servers:

- https://thehackernews.com/2025/02/malicious-ml-models-found-on-hugging.html (Feb 2025)

- https://arstechnica.com/security/2024/03/hugging-face-the-github-of-ai-hosted-code-that-backdoored-user-devices/ (Mar 2024)



In this session, you'll learn 1) how to instrument and detect malicious payloads in AI models and 2) how recent enhancements to ClamAV are protecting customers from supply chain compromises in the era of AI.



Working understanding of Python programming is expected.
</details>

<details>
  <summary>WHIDBOARD: Plug It In, Set It Up & Get Ready to Hack!</summary>
  WHIDBOARD is the ultimate tool-suite for Hardware Hackers. It is designed to act as the perfect Swiss-Army-Knife for hacking any (I)IoT &amp; Embedded devices. Thanks to its core controller (a.k.a. BRUSCHETTAPRO) it can support the interaction with multiple protocols (i.e. UART, SPI, I2C, JTAG &amp; SWD) as well as different Logic Levels (i.e. 1.8V, 2.5V, 3.3V and the VREF of the target itself). Nonetheless, it also allows the hacker to enumerate (UART, JTAG &amp; SWD) thanks to its 24 channels' Pin Enumerator feature, as well as the ability to act as a 8 channels Logic Analyzer at 24MHz.
</details>

<details>
  <summary>CQURE Automatic Destinations Toolkit: Forensics, AppID Analysis & Jump List Reverse Engineering</summary>
  The CQURE Automatic Destinations Toolkit is a forensic and research-grade collection of tools designed to analyze and interpret Windows Automatic Destinations (*. automaticDestinations-ms) files — a rich but underutilized source of timeline and user activity data. These binary files, associated with Jump Lists, contain detailed historical evidence of user interaction with applications and files. The tools are used internally by the CQURE Team in advanced forensics and have been developed based on real-world investigations requiring deep binary parsing and timeline construction from partially overwritten storage devices.

This toolkit enables analysts to calculate, identify, and resolve AppIDs used in Windows Jump Lists, decode file naming schemes based on process names or paths, and extract forensic details such as MAC addresses and hostnames from Automatic Destinations files. It also allows testers and researchers to simulate applications with arbitrary AppIDs and manipulate it. CQURE's reverse engineering of Automatic Destinations led to using in the toolkit some of the undocumented features that are not described in any of the books. 



The toolkit enables analysts to:

1. Calculate, identify, and resolve AppIDs used in Jump Lists

2. Decode file naming schemes

3. Extract forensic details like MAC addresses and hostnames

4. Convert Jump List data into readable, structured XML and HTML

5. Simulate or register custom AppIDs for application behavior testing

6. Manipulate the content of Automatic Destinations

7. Automatically analyze all of the files during the analysis and generate a report to support forensics and incident response operations



How this is useful?

1. Provides deep insight into Jump List activity for timeline and usage analysis.

2. Helps correlate AppIDs with actual applications for investigative purposes.

3. Enables reverse engineering of forensic artifacts tied to user behavior.

4. Allows researchers to simulate or manipulate AppIDs, improving understanding of how Windows ties recent files to apps.



Why is this cool?

1. First toolkit combining AppID resolution, file name calculation, and file content decoding.

2. Supports both live system analysis and offline forensic workflows.

3. Provides a structured XML export of Jump List contents for automation and report building.

4. Helps answer key forensic questions like: "Which file was opened, when, and from where?"



Who is it for?

1. Forensic analysts

2. Threat hunters

3. Incident responders

4. Security researchers

5. Malware analysts
</details>

<details>
  <summary>DroidGround: A Flexible Playground for Android CTF Challenges</summary>
  DroidGround is an application that enables hosting new kinds of Android CTF challenges. It allows to setup a remotely accessible Android jailed to the target application and provides a series of features to allow the player to solve the challenge and get the flag directly from the web application. In this way it is possible to create challenges in which the player has to get RCE on the device to read the flag form a text file on the device.
</details>

<details>
  <summary>PowerPwn Uncovered: Advanced Agentic Recon & Exploitation</summary>
  Reconnaissance in the age of AI Agents demands ever-evolving tactics and tools, which in turn introduce novel risks, including data leakage, unauthorized tool usage, and destructive actions. 



This presentation showcases agentic reconnaissance through an exploration of PowerPwn, an open-source toolkit designed for identifying and exploiting misconfigurations and publicly exposed AI-driven applications, including Microsoft Copilot Studio, Custom ChatGPT bots, and Model Context Protocol (MCP) services.



We start by introducing foundational recon techniques specifically tailored to Copilot Studio bots, then advance into more sophisticated methods for discovering and enumerating other AI-driven platforms. Red teamers will gain insights into the intricacies of agentic OSINT (Open-Source Intelligence), learning practical methods attackers utilize to discover and exploit exposed agent-driven resources.
</details>

<details>
  <summary>ReForge: Where Crashes Become Weapons</summary>
  Fuzzing has become excellent at breaking things, but turning those breakages into real, reproducible, and explainable exploits still takes hours of human effort. ReForge aims to change that.



ReForge is an AI-powered pipeline that takes binary crash artefacts from AFL++ and automatically forges them into working proof-of-concept exploits; complete with human-readable analysis reports. Under the hood, it integrates a multi-agent system: a cloud-based LLM generates the exploit, a local custom-AI model explains it, and a lightweight coordinator (MCP) manages validation and retry logic. Each exploit is auto-tested against an un-instrumented target binary before being stored with metadata and analysis, making the results immediately actionable.



Unlike traditional fuzzing frameworks that stop at a crash log, ReForge picks up the baton and sprints to the finish line: an actual, working Python exploit: readable, reproducible, and explainable. From command injection to buffer overflows, ReForge doesn't just find the bugs,  it teaches you how to weaponize them.



This Arsenal demo will showcase ReForge in action across multiple bug classes, with full visibility into the crash → exploit → analysis lifecycle. Whether you're a red teamer, vulnerability researcher, or just tired of manually triaging crash dumps, ReForge might just be your new favorite ally.
</details>

<details>
  <summary>SAMLSmith</summary>
  SAMLSmith is the go-to tool for penetrating SAML applications with response forging. An evolution of the original tooling developed for proof-of-concept of SAML response forging in Entra ID, SAMLSmith takes further research around SAML response forging and combines it into a tool crafted for offensive scenarios.



While far from new, enterprises continue to not prioritize the security of how SaaS applications integrate or understand best practices for securing them. With many factors at play, SAML response forging can range from extremely difficult to near impossible for a SOC to detect.



SAMLSmith has a lot of tricks up its sleeve, including:

- Multiple identity provider response forging

- AD FS specific response forging mode

- SAML request processing

- InResponseTo support



SAMLSmith can be used in several response forging scenarios where the private key material can be obtained. In demonstration of use, we'll explore using SAMLSmith for performing a Golden SAML attack against AD FS. Further, we'll demonstrate the use of SAMLSmith that ties into new research around response forging, penetrating certain types of SaaS applications with even more stealth.



Using SAMLSmith requires a certain level of knowledge about the target environment, much of which can be gained with other commonly known and used tools that perform reconnaissance against the targeted identity provider.
</details>

<details>
  <summary>Virga: Local LLM Embedded C2 Framework</summary>
  Virga is a new cross-platform command &amp; control (C2) framework powered by a local large language model (LLM). This framework can generate a beacon implant with an embedded LLM, and perform autonomous post-exploitation actions on a target system. In other words, the embedded LLM model autonomously generates and executes the appropriate command based on the situation. Additionally, each beacon has an in-memory database (MemDB) in which the command results are saved in order to improve subsequent actions.

Virga supports the Model Context Protocol (MCP), natural language interactions and Beacon Object Files (BOFs). The MCP specification, including all standard transport methods such as stdio, Server-Sent Events (SSE) and streamable HTTP, has been fully implemented to this framework. This enables Virga to seamlessly integrate with any MCP-compatible AI assistant like Claude and ChatGPT, to perform various additional operations. For example, users can send command instructions to beacons from the ChatGPT UI.

Natural language interactions can mainly be used for beacon operations. This allows beacons to be operated by user's natural language prompts and complete complex tasks simultaneously.

Finally, BOFs make it easy to add new features and tools as extensions to Virga. Therefore, external public tools for post-exploitation can be used in the beacon process through this feature.

The Virga C2 framework simulates the various ways in which modern LLM technology can be exploited.
</details>

<details>
  <summary>AI Wargame</summary>
  Come join a fun and educational attack and defence AI wargame. You will be given an AI chatbot. Your chatbot has a secret that should always remain a secret! Your objective is to secure your chatbot to protect its secret while attacking other players' chatbots and discovering theirs. The winner is the player whose chatbot survives the longest (king of the hill). All skill levels are welcomed, even if this is your first time seeing code, securing a chatbot, or playing in a wargame.



Right at the start, there will be a briefing to show how to play in the wargame. Knowledge of the OpenAI Python SDK helps but is not a requirement. Each player has access to their chatbot source code repository where they can run, test, debug and push their changes.
</details>

<details>
  <summary>Capture the Train: Purple Team Edition!</summary>
  <p><span>Monitoring is often seen as a silver bullet for ICS security—but how effective is it really? In this Arsenal demo lab, you'll launch real attacks against an industrial setup composed of PLCs and SCADA controlling a model train and robotic arms. We'll assess which attacks are detected (or not!), leveraging two newly released plugins we developed to add more ICS capabilities to MITRE CALDERA: <a style="outline: none;" href="https://github.com/wavestone-cdt/caldera-s7" data-mce-href="https://github.com/wavestone-cdt/caldera-s7" data-mce-style="outline: none;">caldera-s7</a> and <a style="outline: none;" href="https://url.us.m.mimecastprotect.com/s/nbcKCyP6mEt06v4NQcNt6uxz-L6?domain=urldefense.com" data-mce-href="https://url.us.m.mimecastprotect.com/s/nbcKCyP6mEt06v4NQcNt6uxz-L6?domain=urldefense.com" data-mce-style="outline: none;">caldera-opcua.</a></span></p>
</details>

<details>
  <summary>Atomic Honeypot - A Tool That Can Hack Back the Attackers Who Are Trying to Connect to Your Database</summary>
  <p><span>In 2023 we discovered a new vector - MySQL server can attack client and presented it at HitB in Amstedam (https://conference.hitb.org/hitbsecconf2023ams/session/how-mysql-servers-can-attack-you/). Later on we have discovered 2 new CVEs in MySQL client libraries and tools, including backup tools. That allowed us to create a new tool, Atomic Honeypot, which targets attackers who are trying to delete your MySQL database. The Atomic Honeypot was first presented at Defcon 2024 (PDF). Since then we found additional CVEs in both MySQL and PostgreSQL and adapted the tool to work with PostgreSQL backup tools (pg_dump, pg_restore), allowing us to explore more PostgreSQL database attacks as well as attacking back the attackers.</span>

<span>We are presenting the new Atomic Honeypot opensource tool (rogue server) with the added ability to counter attack ("hack back") MySQL and PostgreSQL bots. We will do a realtime demo showing how tool works and how various attacker's bots are trying to connect to install malware or delete a database and insert a ransomware note. We will show how the tool can "hack back" using various CVEs we discovered in MySQL and PostgreSQL client libraries.</span></p>
</details>

<details>
  <summary>Ghosts in the DOM: Hunting and Exploiting Hidden postMessage Listeners Using FrogPost Extension</summary>
  FrogPost: Advanced postMessage Security Analyzer



FrogPost is a browser extension for advanced postMessage security analysis. It dynamically discovers event handlers and performs AST-based static analysis to track data taint, identify common sinks (like eval or innerHTML), and crucially, extract the conditional logic (e.g., if (event.data.type === 'chat')) that guards these sinks.



FrogPost generates both general-purpose "dumb" fuzzing payloads and "smart" payloads. Its smart payloads are specifically crafted by attempting to satisfy the identified handler conditions, aiming to effectively reach and test potentially guarded vulnerabilities. The tool delivers comprehensive reports detailing findings, a quantifiable security score, and all generated payloads, empowering testers and developers to uncover and address complex postMessage vulnerabilities.
</details>

<details>
  <summary>LLMMobile v2 - Smart Vulnerability Scanner for Mobile Apps</summary>
  This tool provides a unified solution for mobile app security analysis, supporting both static inspection for Android and iOS apps and dynamic runtime analysis for Android applications. It enhances testing depth through autonomous exploration agents that simulate real user interactions, uncovering hidden risks that traditional methods might miss. An AI-based reasoning layer further improves accuracy by reducing false positives and contextualizing vulnerabilities. Designed for scalability and usability, the tool features a centralized dashboard and integrates smoothly into existing development pipelines.
</details>

<details>
  <summary>NeitherScan: Mass Scanner for a Potential Vulnerability in Windows Kernel Drivers</summary>
  One way that user space applications in Windows interact with kernel drivers is via IOCTL. Applications and drivers pass data back and forth based on IOCTL code. When this code contains a flag METHOD_NEITHER, applications can pass any buffers for input and output directly to the kernel space. This flag could serve as a red flag for CWE-781 (Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code). Related vulnerabilities have been found repeatedly.



Despite its simplicity, there's no automation tool that finds IOCTL codes with METHOD_NEITHER embedded in drivers. Let's say there're 1000 drivers. We must analyze them all manually by loading them in decompiler and reverse-engineer codes.



To automate this process, we developed NeitherScan. It statically scans for METHOD_NEITHER and it works fast, which makes it an ideal tool for bug hunting in a large set of kernel drivers.



We confirmed that NeitherScan detects several CVEs reported in the past. The most recent one is CVE-2024-26229. Audience will not only see how easily potential kernel vulnerabilities can be identified with our tool, but also how our approach can be generalized to automate similar binary analysis tasks.



We've also been using this tool to find zero-day vulnerabilities. In case we find any, we might report them at the venue.
</details>

<details>
  <summary>OWASP EKS Goat: Hands-On AWS EKS Security</summary>
  OWASP EKS Goat is an open source, intentionally vulnerable AWS EKS cluster designed for hands on security testing and learning. It provides a realistic vulnerable environment to explore supply chain vulnerabilities that can lead to the compromise of AWS Cloud resources, including EKS and ECR, through cloud &amp; RBAC misconfigurations.



- Participants can engage in scenarios such as:

    - CVE vulnerable supply chain application serving as an AWS entry point.

    - Exploiting misconfigured IAM roles and Kubernetes RBAC policies.

    - Backdooring AWS ECR images and deploying them within EKS clusters.

    - Performing privilege escalation from compromised pods to EC2 nodes.

    - Documentation includes implementing EKS security practices and hardening using tools like Kyverno, GuardDuty, and eBPF-based runtime security.



This tool is ideal for security professionals, cloud engineers, and DevOps teams aiming to deepen their understanding of cloud managed Kubernetes security (EKS) in AWS environments.
</details>

<details>
  <summary>SupplyShield: Protecting Your Software Supply Chain</summary>
  SupplyShield is a robust security framework designed to protect against complex software supply chain attacks. It helps organizations seamlessly integrate supply chain security into their Software Development Lifecycle (SDLC), addressing the challenges of managing hundreds of microservices and thousands of daily builds.

SupplyShield focuses on generating a Software Bill of Materials (SBOM) and performing Software Composition Analysis (SCA) for microservices.

SupplyShield is built for scalability, enabling SBOM generation and SCA in CI/CD environments with thousands of daily builds. It ensures rapid detection of zero-day vulnerabilities, like the log4j exploit, reducing Mean Time To Detect (MTTD) to minutes and simplifying patch management for security engineers and developers. The framework also includes a dashboard that provides key metrics and actionable insights.

In the latest release, SupplyShield introduces several major updates aimed at further enhancing its capabilities:

Secure Version Identification: The framework now identifies a minimal set of top-level package upgrades that effectively resolve vulnerabilities in deeply nested transitive dependencies.

GitHub Integration for SCA Actionables: All actionable items generated from SCA scans can now be raised directly as GitHub issues within repositories, streamlining collaboration and task management for teams.

EPSS-Based Vulnerability Prioritization: Vulnerabilities are now prioritized using the Exploit Prediction Scoring System (EPSS), enabling teams to focus on the most critical threats.

Build Comparison: SupplyShield now enables users to compare different builds, helping them analyze changes, identify newly introduced packages and vulnerabilities consistency across builds.

With these new features, SupplyShield continues to scale effectively and offers comprehensive tools to help organizations strengthen their software supply chain security with ease and efficiency.
</details>

<details>
  <summary>Exposor - A Contactless Reconnaissance Tool Using Internet Search Engines with a Unified Syntax</summary>
  The attack surface of organizations is constantly evolving, making real-time discovery of exposed technologies and vulnerabilities critical for proactive security. However, conducting searches across multiple Search Engine requires understanding different query syntaxes, which can be time-consuming and inefficient.
</details>


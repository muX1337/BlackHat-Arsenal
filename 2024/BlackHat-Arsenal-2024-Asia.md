<details>
  <summary>AI VPN: A Free-Software AI-Powered Network Forensics Tool</summary>
  The AI VPN is an AI-based traffic analysis tool to detect and block threats, ensuring enhanced privacy protection automatically. It offers modular management of VPN accounts, automated network traffic analysis, and incident reporting. Using the free software IDS system Slips, the AI VPN employs machine learning and threat intelligence for comprehensive traffic analysis. Multiple VPN technologies, such as OpenVPN and Wireguard, are supported, and in-line blocking technologies like Pi-hole provide additional protection.



Developed to assist journalists, activists, and NGOs in combating targeted digital attacks, the AI VPN aims to deliver a user-friendly, efficient, and automated solution for network forensics on devices without requiring physical access. Users experience seamless Internet connectivity, akin to conventional VPNs, while the AI VPN server conducts traffic analysis and reporting.



The AI VPN is designed as a modular collection of micro-services using Docker technology. Ten modules currently handle diverse functionalities such as management, database operations, communication, multiple VPNs, PiHole integration, Slips, and comprehensive reporting.
</details>

<details>
  <summary>Catching adversaries on Azure - Deception on Cloud</summary>
  Cloud is a widely adopted technology for organizations across the globe. It's very often a breeding ground for adversaries as the targets are now reachable to adversaries from anywhere in the world. More often than not, foothold into cloud is just a simple "password-spray" away. How to catch adversaries who are eyeing your crown jewels on cloud? Often adversaries are after your keys, secrets, data, emails, etc. A great way to protect is to put traps everywhere and wait for adversaries to fall into them. But deception on cloud is Hard to create, maintain, monitor, remove and most of all it's pricy. Cloud-Deception is a tool that intends to make it easier for individuals and organizations to deploy, monitor, maintain and remove deception with the most minimal price tag to it. This is done with the help of a CLI suite that creates real-like users (with known weak passwords), real-like resources (such as key vaults, storage accounts, etc.) and real-like identities (Managed identities). All these resources and identities have role assignments randomly assigned and the output is a glorious attack path that's very lucrative for an adversary to pursue. Cloud-deception enables logging automatically and creates alert rules so all you have to do relax and wait for adversaries. Cloud-deception currently supports Microsoft Azure. The talk will consist of a breath-taking tale of how to creation &amp; monitoring of deception on cloud.
</details>

<details>
  <summary>EMBA – From firmware to exploit</summary>
  IoT (Internet of Things) and OT (Operational Technology) are the current buzzwords for networked devices on which our modern society is based on. In this area, the used operating systems are summarized with the term firmware. The devices themselves, also called embedded devices, are essential in the private and industrial environments as well as in the so-called critical infrastructure. 

Penetration testing of these systems is quite complex as we have to deal with different architectures, optimized operating systems and special protocols. EMBA is an open-source firmware analyzer with the goal to simplify and optimize the complex task of firmware security analysis. EMBA supports the penetration tester with the automated detection of 1-day vulnerabilities on binary level. This goes far beyond the plain CVE detection: With EMBA you always know which public exploits are available for the target firmware. Besides the detection of already known vulnerabilities, EMBA also supports the tester on the next 0-day. For this, EMBA identifies critical binary functions, protection mechanisms and services with network behavior on a binary level. There are many other features built into EMBA, such as fully automated firmware extraction, finding file system vulnerabilities, hard-coded credentials, and more.

EMBA is the open-source firmware scanner, created by penetration testers for penetration testers.
</details>

<details>
  <summary>MITRE ATTACK FLOW Detector</summary>
  Converting all kinds of SOC alerts to mitre attack techniques and then finding those few alerts that form a mitre attack flow, seems like a lot of manual work. 



But using a Large Language Model, Knowledge Graph, Temporal Graph Embedding, Density Clustering, and a Markov Model, its now possible to do it automatically in real time.
</details>

<details>
  <summary>Open-Source API Firewall: New Features & Functionalities</summary>
  The open-source API Firewall by Wallarm is designed to protect REST and GraphQL API endpoints in cloud-native environments. API Firewall provides API hardening with the use of a positive security model allowing calls that match a predefined API specification for requests and responses while rejecting everything else.



The key features of API Firewall are:

  - Secure REST and GraphQL API endpoints by blocking non-compliant requests/responses

  - Stop API data breaches by blocking malformed API responses

  - Discover Shadow API endpoints

  - Block attempts to use request/response parameters not specified in an OpenAPI specification

  - Validate JWT access tokens

  - Validate other OAuth 2.0 tokens using introspection endpoints

  - Denylist compromised API tokens, keys, and Cookies
</details>

<details>
  <summary>PentestMuse: The Iron Man Suit of Offensive Security Automation</summary>
  entestMuse is not just a tool; it is the embodiment of the Iron Man philosophy in cybersecurity. Like Tony Stark's exoskeleton, which enhances his abilities while allowing him to retain control and focus on higher-level strategies, PentestMuse augments the capabilities of offensive cybersecurity professionals. It automates the repetitive, precision-dependent tasks of penetration testing - much like the meticulous data collection and alerting in a monitoring system - allowing experts to concentrate on tasks requiring human ingenuity and judgment.



Adhering to the [Compensatory Principle](https://www.notion.so/Compensatory-Principle-efdc076b70d84d1797ab3469a9955ba9?pvs=21), PentestMuse recognizes the distinct strengths of human intuition and machine precision. It executes complex operations autonomously, similar to a state-machine-driven repair system, but steps aside when human intervention is preferable or necessary. This approach mirrors the collaboration between Iron Man's suit and Tony Stark, where automation enhances human skills without overshadowing them.



The design of PentestMuse ensures that the creativity and learning opportunities for cybersecurity professionals are not stifled. The tool works as a partner, handling the 'boring stuff' and late-night work, thereby enabling human experts to focus on creative problem-solving and system optimization. This collaboration is akin to Iron Man's suit: an advanced assistant that elevates the human operator to new levels of efficiency and effectiveness.



In conclusion, PentestMuse is a testament to the power of AI in enhancing human capabilities in offensive security, rather than replacing them. It's a system more Iron Man, less Ultron - a perfect blend of human intelligence and machine efficiency, designed to tackle the ever-evolving challenges of the digital world.
</details>

<details>
  <summary>Slips: A machine-learning based, free-software, P2P Network Intrusion Prevention System</summary>
  For the last 7 years we developed Slips, a behavioral-based intrusion prevention system, and the first free-software network IDS using machine learning. Slips profiles the behavior of IP addresses and performs detections inside each time window in order to also *unblock* IPs. Slips has more than 20 modules that detect a range of attacks both to and from the protected device. It is an network EDR with the capability to also protect small networks. 



Slips consumes multiple packets and flows, exporting data to SIEMs. More importantly, Slips is the first IDS to automatically create a local P2P network of sensors, where instances share detections following a trust model resilient to adversaries.. 



Slips works in several directionality modes. The user can choose to detect attacks coming *to* or going *from* these profiles, or both. This makes it easy to protect your network but also to focus on infected computers inside your network, which is a novel technique.



Among its modules, Slips includes the download/manage of external Threat Intelligence feed (including our laboratory's own TI feed), whois/asn/geocountry enrichment, a LSTM neural net for malicious behavior detection, port scanning detection (vertical and horizontal) on flows, long connection detection, etc. The decisions to block profiles or not are based on ensembling 

algorithms. The P2P module connects to other Slips to share detection alerts.



Slips can read packets from the network, pcap, Suricata, Zeek, Argus and Nfdump, and can output alerts files and summaries. Having Zeek as a base tool, Slips can correctly build a sorted timeline of flows combining all Zeek logs. Slips can send alerts using the STIX/TAXII protocol.



Slips web interface allows to clearly see the detections and behaviors, including threat inteligence enhancements. The interface can show multiple Slips runs, summarize whois/asn/geocountry information and much more.
</details>

<details>
  <summary>Automated Audit Simulation</summary>
  This tool enhances the efficiency of auditing processes, providing a user-friendly interface for seamless operation. Its detailed reporting capabilities empower users with comprehensive insights into endpoint security, facilitating informed decision-making. With a commitment to ethical use, legal compliance, and regular updates, the Automated Audit Simulation tool is a valuable asset for organizations seeking robust cybersecurity assessments.



In addition to scrutinizing network connections for VPN and Tor usage, the tool searches for critical event IDs and investigates Outlook profiles for personal user accounts configured on official laptops/desktops. The flexibility to customize assessments allows users to adapt the tool to evolving security threats.
</details>

<details>
  <summary>DetectiveSQ: A Extension Auditing Framework Version 2</summary>
  In the modern digital realm, internet browsers, particularly Chrome, have transcended traditional boundaries, becoming hubs of multifunctional extensions that offer everything from AI-integrated chatbots to sophisticated digital wallets. This surge, however, comes with an underbelly of cyber vulnerabilities. Hidden behind the guise of innovation, malicious extensions lurk, often camouflaged as benign utilities. These deceptive extensions not only infringe upon user privacy and security but also exploit users with unasked-for ads, skewed search results, and misleading links. Such underhanded strategies, targeting the unsuspecting user, have alarmingly proliferated.



In this talk, we will introduce DetectiveSQ Version 2, an enhanced tool revolutionizing the analysis of Chrome extensions. Building on its proven foundation, it now features integrated AI and GPT models for dynamic analysis, sentiment analysis, and sophisticated static analysis capabilities for permissions, local JavaScript, and HTML files. This dual approach offers a comprehensive evaluation, pinpointing potential security and privacy risks within extensions. DetectiveSQ Version 2 will be open source and made available after the talk.
</details>

<details>
  <summary>Genzai - The IoT Security Toolkit</summary>
  With a widespread increase in the adoption of IoT or Internet of Things devices, their security has become the need of the hour. Cyberattacks against IoT devices have grown rapidly and with platforms like Shodan, it has become much easier to scroll through the entire internet and look for just the right target which an attacker wants. To combat such threats it has become necessary for individuals and organisations to secure their IoT devices but when it becomes harder to keep track of them, the chances of unpatched loopholes increase.



To address this concern and give the users a better visibility of their assets, introducing Genzai! Genzai helps users keep track of IoT device-related web interfaces, scan them for security flaws and scan against custom policies for vendor-specific or all cases.

Tool features:

- Bruteforce panels for vendor-specific and generic/common password lists to look for default creds

- Use pre-defined templates/payloads to look for vulnerabilities

- Users can specify scan policies for scanning vendor-specific or all entries
</details>

<details>
  <summary>Malicious Executions: Unmasking Container Drifts and Fileless Malware with Falco</summary>
  Containers are the most popular technology for deploying modern applications. SPOILER ALERT: bypassing well-known security controls is also popular. In this talk, we explain how to use the recent updates in Falco, a CNCF open-source container security tool, to detect drifts and fileless malware in containerized environments. 



As a best practice, containers should be considered immutable. Early this year, Falco introduced new features to detect container drift via OverlayFS, which can spot if binaries are added or modified after the container's deployment. New binaries are often a sign of an ongoing attack.



Of course, attackers can also use more advanced evasion techniques to stay hidden. By using in-memory, fileless execution, attackers can bypass most of the security controls such as drift detection, and still reach their goals with no stress. 



To combat fileless attacks, Falco has also added memfd-based fileless execution thanks to its visibility superpowers on Linux kernel system calls. Combining Falco's existing runtime security capabilities with these two new detection layers forms the foundation of an in-depth defense strategy for cloud-native workloads.



We will walk you through real-world scenarios based on recent threats and malware, demoing how Falco can help detect and respond to these malicious behaviors and comparing drift and fileless attack paths.
</details>

<details>
  <summary>PASTEBOMB</summary>
  The PasteBomb (PB) botnet does not have any C2 (command and control) server.

Instructions are received using GitHub Gist, and results are sent over a Discord Webhook.

Tracing the C2 server back to the operator is the most common way in which botnet operators are compromised. This technology effectively eradicates such a possibility. When combined with robust operational security (OPSEC), this makes it extremely difficult to trace the operator. This is extremely advantageous for groups engaged in penetration testing. PasteBomb possesses the capacity to carry out Commands, launch DDoS attacks on servers, acquire and execute supplementary payloads, extract personal information from targets, and eliminate its presence without leaving any evidence (Self-Destruct).
</details>

<details>
  <summary>Catsniffer</summary>
  Delve into the fascinating world of IoT (Internet of Things) with the CatSniffer - a powerful, multi-protocol, multi-band, and open-source board crafted for exploring, interacting, and potentially compromising IoT devices. This workshop offers an immersive, hands-on experience, teaching you how to create chaos among IoT devices and challenge real-world devices like property trackers.



Our engaging demonstrations are merely the tip of the iceberg of what you can achieve with the CatSniffer. The tool's exceptional flexibility allows the use of different tools for your security auditing needs, and our unique firmware broadens your learning horizon and amplifies the fun factor, irrespective of whether you're a novice or a seasoned expert in the field.



We invite you to join us on this journey of discovery, where we will harness the boundless capabilities of CatSniffer, fine-tuning your skills and transforming you into a maestro of IoT security auditing.
</details>

<details>
  <summary>.NET Unpacking: When Frida Gets the JIT out of It</summary>
  .NET-based malware families (like AgentTesla, CrimsonRat, and MassLogger, to list a few) can include obfuscation or packing that would harden analysts' work to understand and mitigate these threats effectively. Several options exist for researchers to tackle this challenge such as (but not limited to ) De4Dot, JITM (Mandiant 2020), DotDumper (Black Hat 2022), or JitHook (JSAC 2023) ... However, those solutions either don't cover the case where CLR APIs are intercepted by the packer, or do it in a very limited way. Our new tool has been developed to address this issue, adding some notable advancements that hopefully will prove its utility in the field of malware analysis.

Our Frida-Jit-unPacker (FJP) tool uses a passive, less intrusive approach than previous tools, making it less likely to be detected by anti-unpacking-features. It is developed using Python3 and Frida and doesn't impose restrictions on the .NET framework version associated with the sample. The tool is not focused on specific packers, making it generic and flexible. 

One of its improvements compared to previously listed tools is its ability to also recover and fix original tokens from encrypted ones.

In addition, this tool employs several strategies to be more covert in its operations compared to existing solutions. It achieves this by focusing on intercepting lower-level functions, less likely to set off anti-unpacking mechanisms typically employed by packers. This stealthy approach is further enhanced by disassembling the Common Language Runtime (CLR) - strategically placing hooks just before or after likely monitoring points, tactically reducing the chances of triggering packers' anti-unpacking mechanisms.

These enhancements aim to assist analysts and researchers in the evolving 'cat and mouse' game of malware code protection. Hopefully, the tool will prove to be a valuable addition to the researchers' arsenal.
</details>

<details>
  <summary>BlueMap - An Interactive Tool for Azure Exploitation</summary>
  As demonstrated in BlackHat UK &amp; USA 2022 - BlueMap helps cloud red teamers and security researchers identify IAM misconfigurations, information gathering, and abuse of managed identities in interactive mode without ANY third-party dependencies. No more painful installations on the customer's environment, and No more need to custom the script to avoid SIEM detection!



The tool leaves minimum traffic in the network logs to help during red team engagements from on-prem to the cloud. Developed in Python and implemented all Azure integrations from scratch with zero dependencies on Powershell stuff. The idea behind the tool is to let security researchers and red team members have the ability to focus on more Opsec rather than DevOps stuff.
</details>

<details>
  <summary>Damn Vulnerable Browser Extension (DVBE) - Unfold the risks for your Browser Supplements</summary>
  In the ever expanding world of Browser Extensions, security remains a big concern. As the demand of the feature-rich extensions increases, priority is given to functionality over robustness, which makes way for vulnerabilities that can be exploited by malicious actors. The danger increases even more for organizations handling sensitive data like banking details, PII, confidential org reports etc. 



Damn Vulnerable Browser Extension (DVBE) is an open-source vulnerable browser extension, designed to shed light on the importance of writing secure browser extensions and to educate the developers and security professionals about the vulnerabilities that are found in the browser extensions, how they are found &amp; how they impact business. This built-to-be vulnerable extension can be used to learn, train &amp; exploit browser extension related vulnerabilities.
</details>

<details>
  <summary>Moonshot: A Testing Framework for Large Language Models</summary>
  In today's rapidly evolving AI landscape, large language models (LLMs) have emerged as a cornerstone of many AI-driven solutions, offering increasingly remarkable capabilities in use cases like chatbots and code generation. 



However, this advancement also introduces a unique set of security and safety challenges, ranging from data privacy risks, biases in model outputs, ethical implications of AI interactions, to the risks of generating and executing malicious codes when using these new AI systems. Unfortunately, current LLM testing often focuses on evaluating performance over addressing these vulnerabilities.



We present Moonshot – a testing tookit designed specifically for security evaluators, penetration testers, red teamers, and bug-bounty hunters to conduct attacks on large language models. Moonshot distinguishes itself through its extensible and modular design, facilitating the systematic creation, testing and execution of attacks on LLMs. It comes equipped with a suite of pre-defined security vulnerabilities and safety tests, while also offering users the ease of integrating their own tests into the framework. Additionally, Moonshot features a specialised red-teaming interface that drastically streamlines the process of vulnerability assessment across various LLMs for red teamers.



Moonshot is designed with a simple, intuitive, and interactive interface that would be familiar to AI developers and security experts. Additionally, Moonshot is engineered for easy integration into any model development workflow, enabling seamless and repeatable testing for model developers.
</details>

<details>
  <summary>Quark Script - Dig Vulnerabilities in the BlackBox</summary>
  *Innovative &amp; Interactive*

The goal of Quark Script aims to provide an innovative way for mobile security researchers to analyze or pentest the targets (YES, the binaries).



Based on Quark, we integrate decent tools as Quark Script APIs and make them exchange valuable intelligence with each other. This enables security researchers to interact with staged results and perform creative analysis with Quark Script.



*Dynamic &amp; Static Analysis*

In Quark script, we integrate not only static analysis tools (e.g. Quark itself) but also dynamic analysis tools (e.g. objection).



*Re-Usable &amp; Sharable*

Once the user creates a Quark script for a specific analysis scenario. The script can be used for other targets. Also, the script can be shared with other security researchers. This enables the exchange of knowledge.
</details>

<details>
  <summary>APKDeepLens - Android security insights in full spectrum.</summary>
  APKDeepLens is an open-source Python tool for Android app security analysis. It leverages both static and dynamic analysis techniques to identify vulnerabilities. By static analysis examines APK components like permissions and API calls, while dynamic analysis observes real-time behavior. A key feature is "Contextual Vulnerability Mapping," which assesses vulnerabilities within the code and user flow context. The tool also focuses on extracting sensitive information from the source code, highlighting often overlooked security gaps.



The tool effectively detects vulnerabilities listed in the OWASP Top 10 mobile, emphasizing the most critical security risks to Android applications. Demonstrations of these features will be included. APKDeepLens is equipped to generate comprehensive reports in various formats like HTML, PDF, and JSON, aiding in the transition from detection to remediation.
</details>

<details>
  <summary>Chip In-depth Analysis - Where is the Key?</summary>
  Chip-off forensics is an advanced digital data extraction and analysis technique which involves physically removing flash memory chips (IC) from a subject device and then acquiring the raw data using specialized equipment.



Apart from the rework station, it should have a suitable reader or device to retrieve the data/firmware from the chip.  It is an new developed device which can recognize the chip detailed information.  During the lab, the audiences would have opportunity to analyze the common eMMC / UFS chips and discover the secret from it.
</details>

<details>
  <summary>CLay - Reverse Proxy for Concealing and Deceiving Website Informations</summary>
  The beginning of a devastating cybersecurity incident often occurs when an attacker recognize a technology they capable to exploit used in an application. None of our users care about the technology behind an application more than the mal-intent adversaries. CLay offers a unique and powerful features that goes beyond traditional security measures. CLay takes deception to a new level by mimicking the clockwork of a website with false information, as if the website is made with different technology stack. With a quick 3-minutes installation, the primary objective is to mislead and deceive potential attackers, leading them to gather false information about the web application.
</details>

<details>
  <summary>Deceptively Adaptive Honey Net (dahn)</summary>
  Traditional honey nets offer static infrastructure and static responses. In DAHN, the infrastructure is abstracted, with lambda/gpt API (prompts stipulated) returning seemingly native responses to the threat actor, depending on the complexity index defined by the administrator. In other words, responses are dynamically crafted to entrap and retain threat actors, internal and external, in this environment for as long as possible, giving them a balance of false hope and realistic obstacles as they pass through our simulated layers of defense. Our AI-powered honey net mimics a given corporate environment to create a fictitious digital twin and embeds a controlled-level of simulated vulnerabilities/weaknesses to attract, distract, learn from, and attribute threat actors. The outputs are decoys, diversion, fingerprints, IoCs and IoAs, attributes, TTPs and behaviors, and used to augment threat detection and cyber defense strategies.
</details>

<details>
  <summary>Mantis - Asset Discovery at Scale</summary>
  Mantis is an asset inventory framework that has the capability to distribute a single scan across multiple machines, provides easy customization, dashboard support, and advanced alerting capabilities. We have not reinvented the wheel. Rather, we have tried to design an architecture that provides the essential features for a framework that involves the complexity of integrating multiple tools that are outside our control.
</details>

<details>
  <summary>The Go-Exploit Framework</summary>
  The Go-Exploit framework helps exploit developers rapidly develop advanced exploits in the Go programming language. In this talk, we will demonstrate advanced features of the framework such as integration with Shodan, scanning and exploiting through a proxy (including Tor), using Meterpreter and Sliver payloads, using the built-in encrypted reverse shell, adding custom C2, spinning up LDAP JNDI infrastructure, and easily cross compiling to different OS and architectures.



This talk will focus on real-world exploitation and, as such, we will release go-exploit exploits for CVE-2023-46604 (ActiveMQ), CVE-2023-25194 (Druid), and CVE-2022-47966 (Various Manage Engine).
</details>

<details>
  <summary>AceTheGame</summary>
  Ace The Game is an open-source hacking tool designed for manipulating the memory of Android applications enabling users to change and freeze memory values. This tool also has an interesting feature which enables users to bypass payment methods seamlessly. Notably, this tool boasts compatibility with both rooted and non-rooted Android devices.
</details>

<details>
  <summary>BugHog</summary>
  BugHog is a comprehensive framework designed to identify the complete lifecycles of browser bugs, from the code change that introduced the bug to the code change that resolved the bug. For each bug's proof of concept (PoC) integrated in BugHog, the framework can perform automated and dynamic experiments using Chromium and Firefox revision binaries.



Each experiment is performed within a dedicated Docker container, ensuring the installation of all necessary dependencies, in which BugHog downloads the appropriate browser revision binary, and instructs the browser binary to navigate to the locally hosted PoC web page. Through observation of HTTP traffic, the framework determines whether the bug is successfully reproduced. Based on experiment results, BugHog can automatically bisect the browser's revision history to identify the exact revision or narrowed revision range in which the bug was introduced or fixed.



BugHog has already been proven to be a valuable asset in pinpointing the lifecycles of security bugs, such as Content Security Policy bugs.
</details>

<details>
  <summary>eBPFShield: Unleashing the Power of eBPF for OS Kernel Exploitation and Security.</summary>
  Are you looking for an advanced tool that can help you detect and prevent sophisticated exploits on your systems? Look  no further than eBPFShield. Let's take a technical look at some of the capabilities of this powerful technology:



DNS monitoring feature is particularly useful for detecting DNS tunneling, a technique used by attackers to bypass  network security measures. By monitoring DNS queries, eBPFShield can help detect and block these attempts before any damage is done.



IP-Intelligence feature allows you to monitor outbound connections and check them against threat intelligence lists. This  helps prevent command-and-control (C2) communications, a common tactic used by attackers to control compromised  systems. By blocking outbound connections to known C2 destinations, eBPFShield can prevent attackers from  exfiltrating sensitive data or delivering additional payloads to your system.



eBPFShield Machine Learning feature, you can develop and run advanced machine learning algorithms entirely in eBPF. We  demonstrate a flow-based network intrusion detection system(IDS) based on machine learning entirely in eBPF. Our  solution uses a decision tree and decides for each packet whether it is malicious or not, considering the entire previous  context of the network flow.



eBPFShield Forensics helps address Linux security issues by analyzing system calls and kernel events to detect possible  code injection into another process. It can also help identify malicious files and processes that may have been  introduced to your system, allowing you to remediate any security issues quickly and effectively.



During the session, we'll delve deeper into these features and demonstrate how eBPFShield can help you protect your  systems against even the most advanced threats.
</details>

<details>
  <summary>PMDET, a new fuzzing-based detection tool for Android Parcel Mismatch bugs</summary>
  Android has designed Parcel as its high-performance transport to pass objects across processes.

For classes to be serialized by Parcel, developers must implement the methods for writing and reading the object's properties to and from a Parcel container. The inconsistency between those methods implemented by careless developers introduces Parcel Mismatch bugs, often occurring in vendor-customed classes due to lack of public scrutiny.

Parcel Mismatch bugs can be abused by malicious applications to gain system privilege and have been massively exploited in the wild. However, due to the nature of those bugs, it cannot be solved by traditional source-to-sink taint analysis, currently no mature solutions exist to detect Parcel Mismatch bugs.

Here we proposes PMdet, a new fuzzing-based detection tool for Parcel Mismatch bugs.

PMdet is capable of handling different vendors' firmware without actual devices. It loads Parcelable classes from Android firmware, emulates the Android runtime environment for Parcel to work, and fuzz &amp; monitors the serialization and deserialization procedures for mismatches.

We evaluate PMdet with several firmware from different Android vendors, and the results show that PMdet can detect Parcel Mismatch bugs of different causes, including 11 unique undisclosed mismatches, 6 of which are exploitable, and other 5 bugs that have been already confirmed and fixed.
</details>

<details>
  <summary>AI Wargame (Arsenal Lab)</summary>
  Come join a fun and educational attack and defence AI wargame. You will be given an AI chatbot. Your chatbot has a secret that should always remain a secret! Your objective is to secure your chatbot to protect its secret while attacking other players' chatbots and discovering theirs. The winner is the player whose chatbot survives the longest (king of the hill). All skill levels are welcomed, even if this is your first time seeing code, securing a chatbot, or playing in a wargame.
</details>

<details>
  <summary>BinderAPI Scanner & BASS</summary>
  BASS-Environment Synopsis
Binderlabs API Security Simulator (BASS-Env) is an intentionally vulnerable API environment tailored to reflect the OWASP Top 10 API Security Risks of 2023. Its primary goal is to function as a practical training platform for cybersecurity professionals seeking to enhance their API hacking skills and deepen their understanding of API security testing. BASS-Env provides a hands-on experience by allowing users to interact directly with flawed APIs, highlighting the significance of API security within software development.
The OpenAPI 3 Specifications and Postman Collections serve as the main interface, providing comprehensive documentation and enabling direct testing of API endpoints. At the core of BASS-Env lies its Laravel Backend/API Layer and MySQL Database, intentionally incorporating vulnerabilities across a variety of API endpoints. These components collaborate to simulate real-world scenarios, exposing vulnerabilities such as broken authentication, misconfigurations, and improper inventory management.
Moreover, BASS-Env offers laboratory-based scenarios and challenges for participants, integrating manual and scanner testing methods. Scoring mechanisms, feedback loops, hints, and tutorials assist users in comprehending and resolving challenges. The environment prioritizes security and privacy considerations, accessible locally and supported through GitHub for community engagement. Future enhancements aim to broaden the spectrum of API flaws and facilitate effective updates for BASS-Env instances.
 
BASS-Scanner Synopsis
The BASS-Scanner is a Python3-based tool designed to streamline API Security Testing, focusing on identifying vulnerabilities outlined in the OWASP Top 10 API Security Risks of 2023. It offers a quick and efficient scanning process with minimal installation requirements, making it particularly suitable for penetration testers seeking to expedite API Pentest engagements. The tool's customization options, including the ability to tailor wordlists for specific test cases to enhance detection rates.
Key features include detection of various vulnerabilities such as broken object-level authorization, broken authentication, unrestricted resource consumption, server-side request forgery, and more. Its architecture is straightforward, leveraging Python3 and supporting REST and JSON type APIs.
Scanning methodology involves detailed scrutiny of individual API endpoints, employing techniques like fuzzing and header analysis to uncover security flaws. 
User customization is facilitated through options such as specifying scan types and adjusting scanning parameters. Security and privacy considerations ensure that the tool does not handle sensitive information or transmit data to external sources.
Overall, BASS-Scanner offers a promising solution for efficient and comprehensive API security assessments, with ongoing improvements slated for the future.
</details>

<details>
  <summary>Connect to any device from anywhere with ZERO OPEN NETWORK PORTS</summary>
  Imagine connecting to a device remotely from anywhere on the planet without having to open any network ports on either end - that translates to having ZERO NETWORK ATTACK SURFACES.



This is made possible with Atsign's open source No Ports Product suite which is build on the patented Networking 2.0 technology.
</details>

<details>
  <summary>DarkWidow: Dropper/PostExploitation Tool (or can be used in both situations) targeting Windows.</summary>
  This is a Dropper/Post-Exploitation Tool targeting Windows machine.
</details>

<details>
  <summary>Gerobug: The First Open-Source Bug Bounty Platform</summary>
  Organizations often lack the necessary resources and diverse skills to identify hidden vulnerabilities before attackers exploit them. Bug bounty program, which incentivizes ethical hackers to report bugs, emerged to bridge the skills gap and address the imbalance between attackers and defenders.



However, integrating bug bounty program into security strategies remains challenging due to limitations in efficiency, security, budget, and the scalability of consulting-based or third-party solutions.



Gerobug is the first open-source bug bounty platform that allows organizations to establish their own bug bounty platform easily and securely, free of charge.
</details>

<details>
  <summary>Nightingale: Docker for Pentesters</summary>
  Penetration testing is a critical aspect of ensuring the security of any organization's IT infrastructure. However, setting up a testing environment can be time-consuming and complex, requiring the installation of multiple tools, frameworks, and programming languages. Additionally, maintaining consistency across different testing environments can be challenging. As a result, organizations often struggle to effectively perform penetration testing and identify vulnerabilities in their systems.



Nightingale is an open-source tool that aims to address this problem by providing a ready-to-use environment for pentesters. By building on top of Docker, Nightingale eliminates the need to install multiple programming languages and modules, allowing for faster booting and more efficient resource usage on the host machine. Additionally, Nightingale includes a variety of pre-installed penetration testing tools and frameworks, making it easy for organizations to perform vulnerability assessments and penetration testing of any scope.
</details>

<details>
  <summary>BlueMap - An Interactive Tool for Azure Exploitation</summary>
  As demonstrated in BlackHat UK &amp; USA 2022 - BlueMap helps cloud red teamers and security researchers identify IAM misconfigurations, information gathering, and abuse of managed identities in interactive mode without ANY third-party dependencies. No more painful installations on the customer's environment, and No more need to custom the script to avoid SIEM detection!



The tool leaves minimum traffic in the network logs to help during red team engagements from on-prem to the cloud. Developed in Python and implemented all Azure integrations from scratch with zero dependencies on Powershell stuff. The idea behind the tool is to let security researchers and red team members have the ability to focus on more Opsec rather than DevOps stuff.
</details>

<details>
  <summary>findmytakeover - find dangling domains in a multi cloud environment</summary>
  findmytakeover detects dangling DNS record in a multi cloud environment. It does this by scanning all the DNS zones and the infrastructure present within the configured cloud service provider either in a single account or multiple accounts and finding the DNS record for which the infrastructure behind it does not exist anymore rather than using wordlist or bruteforcing DNS servers.
</details>

<details>
  <summary>Mantis - Asset Discovery at Scale</summary>
  Mantis is an asset inventory framework that has the capability to distribute a single scan across multiple machines, provides easy customization, dashboard support, and advanced alerting capabilities. We have not reinvented the wheel. Rather, we have tried to design an architecture that provides the essential features for a framework that involves the complexity of integrating multiple tools that are outside our control.
</details>

<details>
  <summary>MORF - Mobile Reconnaissance Framework</summary>
  MORF - Mobile Reconnaissance Framework is a powerful, lightweight, and platform-independent offensive mobile security tool designed to help hackers and developers identify and address sensitive information within mobile applications. It is like a Swiss army knife for mobile application security, as it uses heuristics-based techniques to search through the codebase, creating a comprehensive repository of sensitive information it finds. This makes it easy to identify and address any potentially sensitive data leak.



One of the prominent features of MORF is its ability to automatically detect and extract sensitive information from various sources, including source code, resource files, and native libraries. It also collects a large amount of metadata from the application, which can be used to create data science models that can predict and detect potential security threats. MORF also looks into all previous versions of the application, bringing transparency to the security posture of the application.



The tool boasts a user-friendly interface and an easy-to-use reporting system that makes it simple for hackers and security professionals to review and address any identified issues. With MORF, you can know that your mobile application's security is in good hands.



Overall, MORF is a Swiss army knife for offensive mobile application security, as it saves a lot of time, increases efficiency, enables a data-driven approach, allows for transparency in the security posture of the application by looking into all previous versions, and minimizes the risk of data breaches related to sensitive information, all this by using heuristics-based techniques.
</details>

<details>
  <summary>Revela: Unlock the Secrets of Move Smart Contracts</summary>
  <div><span>Powered by the secure and robust Move language, emerging blockchains like Aptos and Sui are gaining rapid popularity. However, their increasingly complex smart contracts, which are often entrusted with valuable assets, need to provide users with the ability to verify the code safety. Unfortunately, it has become common for Move-based protocols to be deployed solely in low-level bytecode form, without accompanying source code. Therefore, reconstructing the original source of the on-chain contracts is essential for users and security researchers to thoroughly examine, evaluate and enhance security.</span></div><div><span>
</span></div><div><span>This talk introduces Revela, the first-ever open-source tool designed to decompile Move bytecode back to its original source code, empowering users and researchers with newfound transparency. We will explain how our tool leverages advanced static analysis techniques to recover the original source code structure, including modules, functions, and data types.</span></div><div><span>
</span></div><div><span>The presentation will include some live demonstrations of using Revela to decompile Move bytecode from online transactions. Additionally, we will showcase how our decompiler can be utilized to uncover vulnerabilities in closed-source protocols running on Aptos and Sui blockchains.</span></div>
</details>

<details>
  <summary>R0fuzz</summary>
  Industrial control systems (ICS) are critical to national infrastructure, demanding robust security measures. "R0fuzz" is a collaborative fuzzing tool tailored for ICS environments, integrating diverse strategies to uncover vulnerabilities within key industrial protocols such as Modbus, Profinet, DNP3, OPC, BACnet, etc. This innovative approach enhances ICS resilience against emerging threats, providing a comprehensive testing framework beyond traditional fuzzing methods.
</details>

<details>
  <summary>RedCloud OS : Cloud Adversary Simulation Operating System</summary>
  RedCloud OS is a Debian based Cloud Adversary Simulation Operating System for Red Teams to assess the security of leading Cloud Service Providers (CSPs). It includes tools optimised for adversary simulation tasks within Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP).



Enterprises are moving / have moved to Cloud Model or Hybrid Model and since security testing is a continuous procedure, operators / engineers evaluating these environments must be well versed with updated arsenal. RedCloud OS is an platform that contains: 



- Custom Attack Scripts

- Installed Native Cloud Provider CLI

- 25+ Multi-Cloud Open-Source Tools

- Tools Categorization as per MITRE ATT&amp;CK Tactics

- Support Multiple Authentication Mechanisms

- In-Built PowerShell for Attacking Azure Environment

- Ease to configure credentials of AWS, Azure &amp; GCP &amp; much more...



Inside each CSP, there are three sub-categories i.e, Enumeration, Exploitation, and Post Exploitation. OS categorises tools &amp; our custom scripts as per the above mentioned sub-categories.
</details>

<details>
  <summary>Secure Local Vault - Git Based Secret Manager</summary>
  Problem Statement:

At Companies secrets are being used across various environments for integration and authentication services. However, managing the secrets and preventing incidents from leakage of secrets have been challenging for the organisation. Existing solutions are centralised and warrants considerable code change to be implemented. Following are the problem statement to be resolved:



- To manage and secure the secrets that are currently in plain text across Git, IaC templates, and workloads.

- To implement a secrets manager that is developer friendly and reduces operational overheads.

- To develop a solution that does not expose the secrets even at the compromise of entities storing the credentials. For example, to protect our secrets from CodeCov like incidents.



Solution:

We have developed a Git based secret manager which adopts a secure and decentralised approach to managing, sharing, and storing the secrets. In this approach secrets are stored in an encrypted form in Github repositories of the teams. 



Keys Principles

This implementation follows two important principles

-A developer can be allowed to add or modify secrets, however should not be allowed to view them

-An environment should have a single identity that gives access to all necessary credentials irrespective of the number of projects that are deployed.
</details>

<details>
  <summary>White Phoenix: recovering files from ransomware attacks</summary>
  White Phoenix tool's goal is to help victims of ransomware attacks recover some of their precious lost data. The tool can successfully recover data from encrypted files by ransomware that uses the Intermittent Encryption method (aka Partial Encryption) in the attack. The tool is free and can be used automatically as a service or manually by taking the code from the tool's GitHub repository.

The Tool's Website: https://getmyfileback.com/
The Tool's GitHub: https://github.com/cyberark/White-Phoenix

</details>

<details>
  <summary>ZANSIN</summary>
  ZANSIN is envisioned as a GROUNDBREAKING cybersecurity training tool designed to equip users against the ever-escalating complexity of cyber threats. It achieves this by providing learners with a platform to engage in simulated cyberattack scenarios, supervised and designed by experienced pentesters. This comprehensive approach allows learners to actively apply security measures, perform system modifications, and handle incident responses to counteract the attacks. Engaging in this hands-on practice within realistic environments enhances their server security skills and provides practical experience in identifying and mitigating cybersecurity risks. ZANSIN's flexible design accommodates diverse skill levels and learning styles, making it a comprehensive and evolving platform for cybersecurity education.
</details>

<details>
  <summary>AutoFix: Automated Vulnerability Remediation Using Static Analysis and LLMs</summary>
  AutoFix is an innovative open-source tool that marries static analysis with advanced Large Language Models (LLMs) to automate the detection and remediation of software vulnerabilities. Utilizing cutting-edge models like StarCoder and Salesforce CodeGen2, AutoFix excels in generating precise patches for a wide range of vulnerabilities, identified through robust static analysis methods including Semgrep. Designed for developers, security professionals, and DevSecOps teams, AutoFix streamlines security integration in software development, balancing speed and accuracy in patch deployment. As a community-driven tool, it evolves continuously, embodying the future of automated, secure coding practices.
</details>

<details>
  <summary>DarkWidow: Dropper/PostExploitation Tool (or can be used in both situations) targeting Windows.</summary>
  This is a Dropper/Post-Exploitation Tool targeting Windows machine.
</details>

<details>
  <summary>DefaceIntel-Visionary</summary>
  The purpose of this project is to develop a robust Web Defacement Detection tool that monitors websites for signs of defacement, an attack where the visual appearance of a website is altered by unauthorized users. 



The tool aims to promptly provide alert if a website content is manipulated, which is often a result of cyber attacks such as those carried out by hacktivists. 



The system utilizes two primary detection methods: a) analyzing drastic changes in webpage size and b) scanning for keywords and phrases associated with hacktivism, including those within images, using generative AI such as GPT that has been trained on large data including OSINT.
</details>

<details>
  <summary>Efidrill ——Automated Hunting UEFI Firmware Vulnerability through Data-Flow Analysis</summary>
  UEFI, an early stage in the computer booting process, is susceptible to attacks that disrupt the Secure Boot security mechanism , thereby allowing attackers to inject a type of malicious software known as "UEFI Rootkit." This specialized strain of malware adeptly conceals itself within SMM or BootLoader, granting malevolent actors surreptitious control over a victim's computer for a prolonged period.

Amidst ongoing research into UEFI security, researchers have discovered numerous SMM vulnerabilities, enhancing the robustness of UEFI. Remarkably, the emergence of tools like "efiexplorer" has significantlystreamlined the reverse engineering process for UEFI firmware.

Yet, contentment with the status quo proves untenable. Many latent UEFI vulnerabilities evade conventional detection techniques, with existing UEFI vulnerability detection tools primarily relying on fuzz testing or assembly instruction matching. Regrettably, no publicly available tool exists that can automatically detect and discover UEFI security vulnerabilities through data flow tracking analysis.

Efidrill - The First Open-Source IDA Plugin for Data Flow Analysis of UEFI Firmware.

Efidrill is a tool that enables data flow tracing, taint tracking, automated structure analysis, variable numerical prediction, and automated vulnerability detection for UEFI firmware. It has discovered multiple hitherto unreported vulnerabilities on hardware platforms from eminent vendors such as Asus, Intel, Dell, etc.
</details>

<details>
  <summary>Malware clustering using unsupervised ML : CalMal</summary>
  CalMal uses unsupervised machine learning for categorising and clustering of malware based upon the behaviour of the malware.

Currently CalMal uses data from VirusTotal . 

It provides following functionalities : 

1) Cluster different malware family.

2) Identifying similarities with any APT malware

3) Identify new samples.

4) Providing visual clustering

It can easily be extended to use data from any sandbox.
</details>

<details>
  <summary>Catsniffer</summary>
  Delve into the fascinating world of IoT (Internet of Things) with the CatSniffer - a powerful, multi-protocol, multi-band, and open-source board crafted for exploring, interacting, and potentially compromising IoT devices. This workshop offers an immersive, hands-on experience, teaching you how to create chaos among IoT devices and challenge real-world devices like property trackers.



Our engaging demonstrations are merely the tip of the iceberg of what you can achieve with the CatSniffer. The tool's exceptional flexibility allows the use of different tools for your security auditing needs, and our unique firmware broadens your learning horizon and amplifies the fun factor, irrespective of whether you're a novice or a seasoned expert in the field.



We invite you to join us on this journey of discovery, where we will harness the boundless capabilities of CatSniffer, fine-tuning your skills and transforming you into a maestro of IoT security auditing.
</details>

<details>
  <summary>AceTheGame</summary>
  Ace The Game is an open-source hacking tool designed for manipulating the memory of Android applications enabling users to change and freeze memory values. This tool also has an interesting feature which enables users to bypass payment methods seamlessly. Notably, this tool boasts compatibility with both rooted and non-rooted Android devices.
</details>

<details>
  <summary>CF-Hero</summary>
  All systems, apps, or tools that are internet-facing have to be deployed behind CloudFlare to increase security and stability. As a security engineer, it's experienced that some systems were/are not deployed properly behind CloudFlare. Any attacker, who discovers the system or app in this way, can hack an organisation's applications. 



This tool(CF-Hero) highlights the security risks associated with domains that are not properly configured behind Cloudflare, a content delivery network (CDN) and distributed DNS service provider. The absence of Cloudflare protection exposes these domains to various attacks, increasing the vulnerability of a company's assets.
</details>

<details>
  <summary>ELFieScanner: Advanced process memory threat detection on Linux</summary>
  ELFieScanner looks to address the relative scarcity and immaturity of non-invasive portable in-memory malware scanning capabilities on Linux. It provides detections with greater context and thus value to the investigative capabilities of blue teams.



ELFieScanner inspects live process memory to detect a number of malicious techniques used by threat actors and in particular those which have been incorporated into Linux based user-mode rootkits. ELFieScanner inspects every running process (both x86/x64) and its corresponding loaded shared objects (libraries) to look for evil. It then outputs resultant detection telemetry into a format that can be easily ingested into a SEIM and viewed by Threat hunters or IR consultants. It has been designed to be both low impact and portable to work across numerous Linux distributions both old and new.



ELFieScanner uses 43 custom built and configurable memory heuristics that are constructed through live in-depth binary analysis of both the process image and a corresponding disk backed binary (if present), using this to identify malevolence. It offers four main detection capabilities that identify:

•	Shared Object injection techniques.

•	Entry point manipulation techniques.

•	Shellcode injection and Process hollowing.

•	API Hooking.



The scanner uses a low impact technique of memory collection that doesn't require interrupts to be sent to remote processes, thereby remaining passive and overcoming ptrace() anti-debug techniques used by malware. The configurability of the binary heuristics provides Blue teams a way to tailor the sensitivity of the detections for their particular environment if used as a persistent monitoring solution; or for incident responders to amass as many suspicious events as possible in one-time collection scenarios. In addition, a portable build is also provided overcoming the unwanted and intrusive default Linux behaviour of building tools on host.
</details>

<details>
  <summary>GitArmor: policy as code for your GitHub environment</summary>
  DevOps security does not only mean protecting the code, but also safeguarding the entire DevOps platform against supply chain attacks, integrity failures, pipelines injections, outsider permissions, worst practices, missing policies and more. 



DevOps platforms like GitHub can easily grow in repos, actions, tokens, users, organizations, issues, PRs, branches, runners, teams, wiki, making admins' life impossible. This means also lowering the security of such environment. 



GitArmor is a policy as code tool, that helps companies,teams and open-source creators, evaluate and enforce their GitHub (only for now) security posture at repository or organization level. Using policies defined using yml, GitArmor can run as CLI, GitHub action or GitHub App, to unify visibility into DevOps security posture and strengthen resource configurations as part of the development cycle.
</details>

<details>
  <summary>Nightingale: Docker for Pentesters</summary>
  Penetration testing is a critical aspect of ensuring the security of any organization's IT infrastructure. However, setting up a testing environment can be time-consuming and complex, requiring the installation of multiple tools, frameworks, and programming languages. Additionally, maintaining consistency across different testing environments can be challenging. As a result, organizations often struggle to effectively perform penetration testing and identify vulnerabilities in their systems.



Nightingale is an open-source tool that aims to address this problem by providing a ready-to-use environment for pentesters. By building on top of Docker, Nightingale eliminates the need to install multiple programming languages and modules, allowing for faster booting and more efficient resource usage on the host machine. Additionally, Nightingale includes a variety of pre-installed penetration testing tools and frameworks, making it easy for organizations to perform vulnerability assessments and penetration testing of any scope.
</details>

<details>
  <summary>AI Wargame (Arsenal Lab)</summary>
  Come join a fun and educational attack and defence AI wargame. You will be given an AI chatbot. Your chatbot has a secret that should always remain a secret! Your objective is to secure your chatbot to protect its secret while attacking other players' chatbots and discovering theirs. The winner is the player whose chatbot survives the longest (king of the hill). All skill levels are welcomed, even if this is your first time seeing code, securing a chatbot, or playing in a wargame.
</details>

<details>
  <summary>BucketLoot - An Automated S3 Bucket Inspector</summary>
  Thousands of S3 buckets are left exposed over the internet, making it a prime target for malicious actors who may extract sensitive information from the files in these buckets that can be associated with an individual or an organisation. There is limited research or tooling available that leverages such S3 buckets for looking up secret exposures and searching specific keywords or regular expression patterns within textual files.



BucketLoot is an automated S3 Bucket Inspector that can simultaneously scan all the textual files present within an exposed S3 bucket from platforms such as AWS, DigitalOcean etc.



It scans the exposed textual files for:

- Secret Exposures

- Assets (URLs, Domains, Subdomains)

- Specific keywords | Regex Patterns (provided by the user)



The end user can even search for string based keywords or provide custom regular expression patterns that can be matched with the contents of these exposed textual files.



All of this makes BucketLoot a great recon tool for bug hunters as well as professional pentesters.



The tool allows users to save the output in a JSON format which makes it easier to pass the results as an input to some third-party product or platform.
</details>

<details>
  <summary>GearGoat : Car Vulnerabilities Simulator</summary>
  GearGoat is a python based implementation Car simulator, inspired from the ICSim tool (written in C), to help learners get started with car hacking. The idea is to provide an easy to use simulator with a virtual can interface, webUI interface and most dependencies handled inside a Docker container. This allows users to run this tool on a non-GUI/Qt machine with just a few clicks. Also, as it is written in Python, communities can easily extend it with their own code. The version with ICSim level functionality with webUI and Dockerised environment is already released on GitHub and currently we are working to add common/known vulnerabilities to it to act as a vulnerable target practice car.
</details>

<details>
  <summary>Monitoring and Detecting Leaks with GitAlerts</summary>
  Most organisations put significant effort into maintaining their public GitHub repositories. They safeguard these repositories against various security vulnerabilities and routinely scan for sensitive information, ensuring thorough checks have been carried out before making anything public. However, an aspect that is often overlooked is the monitoring of the public activities of their organisation's users.



Developers within organisations frequently experiment and test ideas in a public setting, which may inadvertently include sensitive code, hardcoded credentials, secrets, internal URLs, and other proprietary information. This oversight can lead to significant security risks, making it crucial for organisations to monitor such activities to prevent potential data breaches.



Recent studies on data breaches reveal a startling trend. The leakage of secrets and sensitive information often occurs via individual repositories, rather than organisational ones. This fact underscores the importance of monitoring not just the organisation's repositories but also those created and maintained by individual users.



This talk aims to shed light on such cases related to GitHub. We will delve into real-world examples, discuss the common pitfalls, and suggest effective strategies to guard against these potential security risks.
</details>

<details>
  <summary>Surfactant - Modular Framework for File Information Extraction and SBOM Generation</summary>
  Surfactant is a modular framework for extracting information from filesystems, primarily for generating an SBOM (Software Bill of Materials). The information extracted can then be used to identify the various vendors or libraries associated with a file, and establish relationships between files. The resulting SBOM can be used for system level impact analysis (such as for IoT, Smart Grid, or ICS devices) of vulnerabilities, and the information gathered can be used to help inform what files to focus on for manual analysis.
</details>

<details>
  <summary>vet: Policy Driven vetting of Open Source Software Components</summary>
  vet is a tool for identifying risks in open source software supply chain. It helps engineering and security teams to identify potential issues in their open source dependencies and evaluate them against codified organisational policies.
</details>

<details>
  <summary>.NET Unpacking: When Frida Gets the JIT out of It</summary>
  .NET-based malware families (like AgentTesla, CrimsonRat, and MassLogger, to list a few) can include obfuscation or packing that would harden analysts' work to understand and mitigate these threats effectively. Several options exist for researchers to tackle this challenge such as (but not limited to ) De4Dot, JITM (Mandiant 2020), DotDumper (Black Hat 2022), or JitHook (JSAC 2023) ... However, those solutions either don't cover the case where CLR APIs are intercepted by the packer, or do it in a very limited way. Our new tool has been developed to address this issue, adding some notable advancements that hopefully will prove its utility in the field of malware analysis.

Our Frida-Jit-unPacker (FJP) tool uses a passive, less intrusive approach than previous tools, making it less likely to be detected by anti-unpacking-features. It is developed using Python3 and Frida and doesn't impose restrictions on the .NET framework version associated with the sample. The tool is not focused on specific packers, making it generic and flexible. 

One of its improvements compared to previously listed tools is its ability to also recover and fix original tokens from encrypted ones.

In addition, this tool employs several strategies to be more covert in its operations compared to existing solutions. It achieves this by focusing on intercepting lower-level functions, less likely to set off anti-unpacking mechanisms typically employed by packers. This stealthy approach is further enhanced by disassembling the Common Language Runtime (CLR) - strategically placing hooks just before or after likely monitoring points, tactically reducing the chances of triggering packers' anti-unpacking mechanisms.

These enhancements aim to assist analysts and researchers in the evolving 'cat and mouse' game of malware code protection. Hopefully, the tool will prove to be a valuable addition to the researchers' arsenal.
</details>

<details>
  <summary>AWSDefenderGPT: Leveraging OpenAI to Secure AWS Cloud</summary>
  AWSDefenderGPT is an AI tool designed to identify and rectify cloud misconfigurations by using Open AI GPT models. AWSDefenderGPT can understand complex queries to detect misconfigurations in cloud environments and provide fixes for them.



This tool merges the capabilities of automated deployment and configuration modification using AI, along with cloud SDK tools. As a result, it transforms into an AI-powered cloud manager that helps you ensure the security of the cloud environment by preventing misconfigurations. By centralizing the process, users can effortlessly address misconfigurations and excessively permissive policies in a single stage, simplifying handling of potential future threats.
</details>

<details>
  <summary>CloudSec Navigator</summary>
  Security incidents on cloud platforms such as AWS are occurring frequently, and many of them are caused by misconfigurations or inappropriate use of features. For the purpose of incident prevention, developers need to read a large amount of documentation, including important security guidelines and best practices. The tool uses Retrieval-Augmented Generation (RAG) and Large Language Models (LLM) vector searches to provide highly accurate, customized security advice and referenced guidelines based on the information retrieved. and best practices information. This allows developers to focus on more efficient and secure software development instead of reading large amounts of documentation.
</details>

<details>
  <summary>exploitdb-images</summary>
  ExploitDBImages aims to automate the exploiting phase of penetration testing through Docker containers. With this tool, testers can easily execute required scripts for the successful exploitation of vulnerable applications, eliminating the need for manual installation of dependencies.
</details>

<details>
  <summary>The Go-Exploit Framework</summary>
  The Go-Exploit framework helps exploit developers rapidly develop advanced exploits in the Go programming language. In this talk, we will demonstrate advanced features of the framework such as integration with Shodan, scanning and exploiting through a proxy (including Tor), using Meterpreter and Sliver payloads, using the built-in encrypted reverse shell, adding custom C2, spinning up LDAP JNDI infrastructure, and easily cross compiling to different OS and architectures.



This talk will focus on real-world exploitation and, as such, we will release go-exploit exploits for CVE-2023-46604 (ActiveMQ), CVE-2023-25194 (Druid), and CVE-2022-47966 (Various Manage Engine).
</details>

<details>
  <summary>AutoFix: Automated Vulnerability Remediation Using Static Analysis and LLMs</summary>
  AutoFix is an innovative open-source tool that marries static analysis with advanced Large Language Models (LLMs) to automate the detection and remediation of software vulnerabilities. Utilizing cutting-edge models like StarCoder and Salesforce CodeGen2, AutoFix excels in generating precise patches for a wide range of vulnerabilities, identified through robust static analysis methods including Semgrep. Designed for developers, security professionals, and DevSecOps teams, AutoFix streamlines security integration in software development, balancing speed and accuracy in patch deployment. As a community-driven tool, it evolves continuously, embodying the future of automated, secure coding practices.
</details>

<details>
  <summary>Chip In-depth Analysis - Where is the Key?</summary>
  Chip-off forensics is an advanced digital data extraction and analysis technique which involves physically removing flash memory chips (IC) from a subject device and then acquiring the raw data using specialized equipment.



Apart from the rework station, it should have a suitable reader or device to retrieve the data/firmware from the chip.  It is an new developed device which can recognize the chip detailed information.  During the lab, the audiences would have opportunity to analyze the common eMMC / UFS chips and discover the secret from it.
</details>

<details>
  <summary>GitArmor: policy as code for your GitHub environment</summary>
  DevOps security does not only mean protecting the code, but also safeguarding the entire DevOps platform against supply chain attacks, integrity failures, pipelines injections, outsider permissions, worst practices, missing policies and more. 



DevOps platforms like GitHub can easily grow in repos, actions, tokens, users, organizations, issues, PRs, branches, runners, teams, wiki, making admins' life impossible. This means also lowering the security of such environment. 



GitArmor is a policy as code tool, that helps companies,teams and open-source creators, evaluate and enforce their GitHub (only for now) security posture at repository or organization level. Using policies defined using yml, GitArmor can run as CLI, GitHub action or GitHub App, to unify visibility into DevOps security posture and strengthen resource configurations as part of the development cycle.
</details>

<details>
  <summary>PASTEBOMB</summary>
  The PasteBomb (PB) botnet does not have any C2 (command and control) server.

Instructions are received using GitHub Gist, and results are sent over a Discord Webhook.

Tracing the C2 server back to the operator is the most common way in which botnet operators are compromised. This technology effectively eradicates such a possibility. When combined with robust operational security (OPSEC), this makes it extremely difficult to trace the operator. This is extremely advantageous for groups engaged in penetration testing. PasteBomb possesses the capacity to carry out Commands, launch DDoS attacks on servers, acquire and execute supplementary payloads, extract personal information from targets, and eliminate its presence without leaving any evidence (Self-Destruct).
</details>

<details>
  <summary>SecDim Play SDK: Build Defensive AI and AppSec Challenges</summary>
  In a typical CTF challenge, the objective is to identify and exploit security vulnerabilities. On the other hand, the aim of a defensive or AppSec challenge is to rectify security vulnerabilities. Historically, building defensive challenges has been challenging due to the requirement for complex tools and infrastructure to manage and review player submissions.

In this presentation, we will introduce SecDim Play SDK: an open-source SDK designed for building defensive, AppSec, and AISec challenges. We will demonstrate how we model security attacks into software tests that can be used to assess players' security patches. In a live demo, we will explore the process of selecting real-world-inspired security vulnerabilities and transforming them into cloud-native apps with integrated security tests. Using Play SDK, we can create new challenges that focus on finding and fixing security vulnerabilities.
</details>

<details>
  <summary>White Phoenix: recovering files from ransomware attacks</summary>
  White Phoenix tool's goal is to help victims of ransomware attacks recover some of their precious lost data. The tool can successfully recover data from encrypted files by ransomware that uses the Intermittent Encryption method (aka Partial Encryption) in the attack. The tool is free and can be used automatically as a service or manually by taking the code from the tool's GitHub repository.

The Tool's Website: https://getmyfileback.com/
The Tool's GitHub: https://github.com/cyberark/White-Phoenix

</details>

<details>
  <summary>MITRE ATTACK FLOW Detector</summary>
  Converting all kinds of SOC alerts to mitre attack techniques and then finding those few alerts that form a mitre attack flow, seems like a lot of manual work. 



But using a Large Language Model, Knowledge Graph, Temporal Graph Embedding, Density Clustering, and a Markov Model, its now possible to do it automatically in real time.
</details>


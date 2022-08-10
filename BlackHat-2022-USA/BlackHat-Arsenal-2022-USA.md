# BlackHat Arsenal 2022 USA

Links to the repositories or other stuff of the BlackHat USA 2022

<details>
  <summary>Vajra - Your Weapon To Cloud</summary>
  
Vajra (Your Weapon to Cloud) is a framework capable of validating the cloud security posture of the target environment. In Indian mythology, the word Vajra refers to the Weapon of God Indra (God of Thunder and Storms). Because it is cloud-connected, it is an ideal name for the tool.
Vajra supports multi-cloud environments and a variety of attack and enumeration strategies for both AWS and Azure. It features an intuitive web-based user interface built with the Python Flask module for a better user experience. The primary focus of this tool is to have different attacking and enumerating techniques all in one place with web UI interfaces so that it can be accessed anywhere by just hosting it on your server.


The following modules are currently available:

• Azure
 - Attacking
 1. OAuth Based Phishing (Illicit Consent Grant Attack)
 - Exfiltrate Data
 - Enumerate Environment
 - Deploy Backdoors
 - Send mails/Create Rules
 2. Password Spray
 3. Password Brute Force
 - Enumeration
 1. Users
 2. Subdomain
 3. Azure Ad
 4. Azure Services
 - Specific Service
 1. Storage Accounts
• AWS
 - Enumeration
 1. IAM Enumeration
 2. S3 Scanner
 - Misconfiguration
 
https://github.com/TROUBLE-1/Vajra
</details>

<details>
  <summary>What's new in reNgine?</summary>
  
reNgine, an automated reconnaissance framework, helps quickly discover the attack surface and identifies vulnerabilities using extremely customizable and powerful scan engines. The most recent update introduces some of the most innovative features such as powerful sub scans feature, highly configurable reconnaissance & vulnerability pdf report, Tools Arsenal which allows updating preinstalled tools, their configurations, WHOIS identification, identifies related domains and related TLDs, and tons of actionable insights such as most common vulnerability, most common CVE IDs, etc. In a nutshell, the newer upgrade of reNgine makes it more than just a recon tool! The latest update aims to fix the gap in the traditional recon tools and probably a much better alternative for some of the commercial recon and vulnerability assessment tools.

This talk will be a walkthrough on some of the newest features to be introduced in reNgine and how corporates and individuals can make the best use of it.

https://github.com/yogeshojha/rengine
</details>

<details>
  <summary>unblob</summary>
  
  One of the major challenges of embedded security analysis is the sound and safe extraction of arbitrary firmware.

Specialized tools that can extract information from those firmwares already exists, but we wanted something smarter that could identify both start offset of a specific chunk (e.g. filesystem, compression stream, archive) and end offset.

We stick to the format standard as much as possible when deriving these offsets, and we clearly define what we want out of identified chunks (e.g., not extracting meta-data to disk, padding removal).

This strategy helps us feed known valid data to extractors and precisely identify unidentified chunks, turning unknown unknowns into known unknowns.

Given the modular design of unblob and the ever expanding repository of supported formats, unblob could be used in areas outside of embedded security such as data recovery, memory forensics, or malware analysis.

unblob has been developed with the following objectives in mind:

* Accuracy - chunk start offsets are identified using battle tested rules, while end offsets are computed according to the format's standard without deviating from it. We minimize false positives as much as possible by validating header structures and discarding overflowing chunks.
* Security - unblob does not require elevated privileges to run. It's heavily tested and has been fuzz tested against a large corpus of files and firmware images. We rely on up-to-date third party dependencies that are locked to limit potential supply chain issues. We use safe extractors that we audited and fixed where required (e.g., path traversal in ubi_reader, path traversal in jefferson, integer overflow in Yara).
* Extensibility - unblob exposes an API that can be used to write custom format handlers and extractors in no time.
* Speed - we want unblob to be blazing fast, that's why we use multi-processing by default, make sure to write efficient code, use memory-mapped files, and use Hyperscan as high-performance matching library. Computation intensive functions are written in Rust and called from Python using specific bindings.

https://github.com/onekey-sec/unblob
</details>

<details>
  <summary>stegoWiper: A powerful and flexible active attack for disrupting stegomalware</summary>

Over the last 10 years, many threat groups have employed stegomalware or other steganography-based techniques to attack organizations from all sectors and in all regions of the world. Some examples are: APT15/Vixen Panda, APT23/Tropic Trooper, APT29/Cozy Bear, APT32/OceanLotus, APT34/OilRig, APT37/ScarCruft, APT38/Lazarus Group, Duqu Group, Turla, Vawtrack, Powload, Lokibot, Ursnif, IceID, etc.
Our research shows that most groups are employing very simple techniques (at least from an academic perspective) and known tools to circumvent perimeter defenses, although more advanced groups are also using steganography to hide C&C communication and data exfiltration. We argue that this lack of sophistication is not due to the lack of knowledge in steganography (some APTs have already experimented with advanced algorithms) but simply because organizations are not able to defend themselves, even against the simplest steganography techniques.
During the demonstration we will show the practical limitations of applying existing automated steganalysis techniques for companies that want to prevent infections or information theft by these threat actors.
For this reason, we have created stegoWiper, a tool to blindly disrupt any image-based stegomalware, attacking the weakest point of all steganography algorithms: their robustness. We'll show that it is capable of disrupting all steganography techniques and tools (Invoke-PSImage, F5, Steghide, openstego, ...) employed nowadays, as well as the most advanced algorithms available in the academic literature, based on matrix encryption, wet-papers, etc. (e.g. Hill, J-Uniward, Hugo). In fact, the more sophisticated a steganography technique is, the more disruption stegoWiper produces.
Moreover, our active attack allows us to disrupt any steganography payload from all the images exchanged by an organization by means of a web proxy ICAP (Internet Content Adaptation Protocol) service, in real time and without having to identify which images contain hidden data first.

https://github.com/mindcrypt/stegowiper  
</details>

<details>
  <summary>Siembol: An Open-Source Real-Time SIEM Tool Based on Big Data Technologies</summary>
  
Siembol is an in-house developed security data processing application, forming the core of an internal Security Data Platform.

Following the experience of using Splunk, and as early adopters of Apache Metron, the team needed a highly efficient, real-time event processing engine with fewer limitations and more enhanced features. With Metron now retired, Siembol hopes to give the community an evolved alternative.

Siembol improvements over Metron:
- Components for real-time alert escalation: CSIRT teams can easily create a rule-based alert from a single data source, or they can create advanced correlation rules that combine various data sources. Moreover, Siembol UI supports importing a Sigma rule into Siembol alerting.
- Ability to integrate with other systems using dedicated components and plugin architecture for easy integration with incident response tools
- Advanced parsing framework for building fault-tolerant parsers
- Enhanced enrichment component allowing for defining rules and joining enrichment tables
- Configurations and rules are defined by a modern Angular web application, with a git-based approval process
- Supports OAuth2/OIDC for authentication and authorization in Siembol UI
- Easy installation for use with prepared docker images, helm charts and quick start guide

Siembol Use Cases:
- SIEM log collection using open-source technologies
- Detection tool for discovery of leaks and attacks on infrastructure
- Real-time stream Sigma rule evaluation without the need to index logs

https://github.com/G-Research/siembol  
</details>

<details>
  <summary>SMBeagle</summary>

SMBeagle is an SMB file share auditing and enumeration tool that rapidly hunts out file shares and inventories their contents. Built from a desire to find poorly protected files, SMBeagle casts the spotlight on files vulnerable to ransomware, watering hole attacks and which may contain sensitive credentials.

SMBeagle hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host?

Businesses of all sizes often have file shares with awful file permissions.

Large businesses have sprawling file shares and its common to find sensitive data with misconfigured permissions and small businesses often have a small NAS in the corner of the office with no restrictions at all!

SMBeagle crawls these shares and lists out all the files it can read and write. If it can read them, so can ransomware.

SMBeagle can provide penetration testers with the less obvious routes to escalate privileges and move laterally.

By outputting directly into elasticsearch, testers can quickly find readable scripts and writeable executables.

Finding watering hole attacks and unprotected passwords never felt so easy!
  
https://github.com/punk-security/smbeagle 
</details>

<details>
  <summary>SCMKit: Source Code Management Attack Toolkit</summary>

Source Code Management (SCM) systems play a vital role within organizations and have been an afterthought in terms of defenses compared to other critical enterprise systems such as Active Directory. SCM systems are used in the majority of organizations to manage source code and integrate with other systems within the enterprise as part of the DevOps pipeline, such as CI/CD systems like Jenkins. These SCM systems provide attackers with opportunities for software supply chain attacks and can facilitate lateral movement and privilege escalation throughout an organization.

This presentation will announce the public release of SCMKit, a toolkit that can be used to attack SCM systems. SCMKit allows the user to specify the SCM system and attack module to use, along with specifying valid credentials (username/password or API key) to the respective SCM system. Currently, the SCM systems that SCMKit supports are GitHub Enterprise, GitLab Enterprise and Bitbucket Server. The attack modules supported include reconnaissance, privilege escalation and persistence. SCMKit was built in a modular approach, so that new modules and SCM systems can be added in the future by the information security community.

https://github.com/xforcered/SCMKit  
</details>

<details>
  <summary>RIDE: Efficient Highly-Precise Systematic Automatic Bug Hunting in Android Systems</summary>

Vulnerabilities in various android systems such as the AOSP and vendor-specific components directly impact user security & privacy and should be eliminated. Do we have a way to efficiently identify bugs in ready-to-ship phones conveniently and precisely? From a researcher perspective, vendor codes are mainly closed-source which means they cannot use open-source auditing tools and usually the only obtainable resource is phone firmware. From vendor QA and security team's perspective, the ability to perform a systematic vulnerability assessment directly on ready-to-ship phone images would also be much more useful and easier than maintaining complex dependency and version information on each model.

We come up with a framework named RIDE (Rom Intelligent Defect assEsment) that directly operates on factory images of major android systems such as AOSP, Samsung, Huawei, Xiaomi, Oppo etc, which discovered 40+ CVEs including critical and high severity level bugs in the vendors in less than one year. RIDE combines highly precise whole-program static taint analysis and dynamic blackbox binary fuzzing to pinpoint vulnerabilities in user-space code such as system apps, system services and bundled closed-source libraries. In this talk, we will share in detail about the system's design and architecture, including the whole-program static analysis algorithm and implementation with high precision and acceptable performance, and the blackbox fuzzing component which is fed by the information collected from previous static analysis. Also, we will share the detail and exploitation of several bugs found, which range from system-level arbitrary file read/write/code execution to RCE ones in AOSP and other major vendors etc.

INFO: Couldn't find this tool on github but here is his profile: https://github.com/flankerhqd
</details>

<details>
  <summary>ReconPal: Leveraging NLP for Infosec</summary>

Recon is one of the most important phases that seem easy but takes a lot of effort and skill to do right. One needs to know about the right tools, correct queries/syntax, run those queries, correlate the information, and sanitize the output. All of this might be easy for a seasoned infosec/recon professional to do but for rest, it is still near to magic. How cool it will be to ask a simple question like "Find me an open Memcached server in Singapore with UDP support?" or "How many IP cameras in Singapore are using default credentials?" in WhatsApp chat or a web portal and get the answer?

The integration of GPT-3, deep learning-based language models to produce human-like text, with well-known recon tools like Shodan is the foundation of ReconPal. In this talk, we will be introducing ReconPal with report generation capabilities and interactive terminal sessions. We are also introducing a miniature attack module, allowing users to execute popular exploits against the server with just the voice commands. The code will be open-source and made available after the talk.
  
https://github.com/pentesteracademy/reconpal  
</details>

<details>
  <summary>ParseAndC 2.0 – We Don't Need No C Programs (for Parsing)</summary>

This is the 2.0 version of the ParseAndC tool that was presented in BH and DEFCON last year, with many new features added. The 1.0 version was capable of mapping any C structure(s) to any datastream, and then visually displaying the 1:1 correspondence between the variables and the data in a very colorful, intuitive display so that it was very easy to understand which field had what value.

In 2.0 version, we essentially expand the C language so that C structures alone has the same power as full-fledged C programs. We introduce Dynamic structure, which changes depending on what data it has seen till now. It supports variable-sized array, variable-sized bitfield, and addition/deletion of struct members depending on what value the previous struct members have. Suppose we are parsing the network packets, and after we decode the IP header, depending on the protocol field this tool can automatically decode the next header as either the TCP or UDP. We also add speculative execution, where user just provides the key expected values of certain fields (like magic numbers, mentioned by C initializations), and the tool automatically finds out from which offset to map so that all fields indeed have the expected value.

This tool is extremely portable – it's a single Python 1MB text file, is cross-platform (Windows/Mac/Unix), and also works in the terminal /batch mode without GUI or Internet connection. The tool is self-contained - it doesn't import anything, to the extent that it implements its own C compiler (front-end) from scratch!!

This tool is useful for both security- and non-security testing alike (reverse engineering, network traffic analyzing, packet processing etc.). It is currently being used at Intel widely. The author of this tool led many security hackathons at Intel and there this tool was found to be very useful.

https://github.com/intel/ParseAndC  
  
</details>

<details>
  <summary>Node Security Shield - A Lightweight RASP for NodeJS Applications</summary>
  
Node Security Shield (NSS) is an Open source Runtime Application Self-Protection (RASP) tool which aims at bridging the gap for comprehensive NodeJS security.
NSS is designed to be Developer and Security Engineer friendly and enables them to declare what resources an application can access.
Inspired by the Log4Shell vulnerability which can be exploited because an application can make arbitrary network calls, we felt there is a need for an application to have a mechanism so that it can declare what privileges it allows in order to make the exploitation of such vulnerabilities harder by implementing additional controls.
In order to achieve this, NSS (Node Security Shield) has a Resource Access Policy and the concept is similar to CSP (Content Security Policy). Resource Access Policy lets developer/security engineers declare what resources an application should access and Node Security Shield will enforce it.
If the Application is compromised and requests 'attacker.com' Node Security Shield will block it automatically and thus protect the application from malicious attacks.
Node Security Shield was first announced in Black Hat Asia 2022 Arsenal. This is the first major update after its release. This release adds support for the 'module-level' Resource Access Policy.
Allowing Developers or Security Engineers to declare what resources a module can access. 

https://github.com/DomdogSec/NodeSecurityShield 
</details>

<details>
  <summary>MUSHIKAGO-femto: Automated Pentest & First Aid Tool for IT/OT Environments</summary>
 
At the Black Hat USA 2021 Arsenal, we presented MUSHIKAGO, an automated penetration testing tool for both IT and OT. MUSHIKAGO can automatically perform penetration tests and post-exploitation in various environments without prior learning.

This time, we have newly evolved MUSHIKAGO as MUSHIKAGO-femto, incorporating cutting-edge features. The evolution includes the implementation of a mechanism to perform first aid on the tested system and acquire immune functions so that the same attack can be defended against attacks that could be achieved by penetration tests. A function was implemented to defend against vulnerability attacks by applying patches, injecting FW functions or proprietary IPS into terminals. Specifically, taking advantage of the fact that the penetration test was able to penetrate the system, patches are applied as if injecting a vaccine at the penetrated terminal, or a unique thin IPS is incorporated. This allows the system to be defended before the actual attacker can exploit the vulnerability or misconfiguration. Based on these results, MUSHIKAGO-femto has become the Next-Generation Pentest Tool that strengthens system defenses while performing penetration testing.

Other additional features include the implementation of a scan function to detect ICS protocols in order to detect ICS devices with high accuracy. MUSHIKAGO-femto has both Active Scan and Passive Scan functions, enabling comprehensive detection of PLCs and ICS devices. This enables automatic penetration of OT system. This makes it possible to perform automatic penetration tests on OT system with high accuracy. In the demo, we will show how it can perform automatic penetration testing and automatic protection against Hack THe Box and VulnHub machines. We will also show that it is possible to perform effective penetration testing in our OT/ICS environment.

https://github.com/PowderKegTech/mushikago-femto 
  
</details>

<details>
  <summary>In0ri: Open Source Defacement Detection With Deep Learning</summary>

In0ri is the first open source system for detecting defacement attacks by utilizing image-classification convolutional neural network. In this presentation, we will be demonstrating the process of setting up In0ri and have it detect defacement attacks. And optionally the process of training the machine learning model. We will also be explaining the reason behind In0ri's high accuracy when classifying defacement attacks.
  
https://github.com/J4FSec/In0ri 
</details>

<details>
  <summary>Hooke: A Sandbox Tool for both Android and iOS Apps</summary>
  
Mainstream mobile phone systems have implemented privacy features that allow users to keep an eye on how apps access their data, such as Privacy Dashboard for Android and App Privacy Report for iOS. However, while we delved into the implementation of these systems, we found that it was not as accurate and credible as expected. We developed our offline App privacy leak detection platform - Hooke, to identify privacy-sensitive behaviors much more clearly and directly.

For data access, we identified over 300 privacy-related APIs across 8 categories for both Android and iOS, and we constructed sandbox environments and added instrumentation to collect runtime information like parameters, stack traces and app status. For network behavior, we found a general solution to bypass ssl pinning, and tried to decrypt network traffic to prevent sensitive data escape. To facilitate locating privacy issues, our sandbox also recorded App runtime screens and timestamps during the test phase, which are associated directly with dynamic behaviors.

Our tool, Hooke, shows App behaviors in the aspect of privacy data access, network traffic and screen recordings, and we also implemented an intelligent rule engine to analyze this data. Finally, these three categories data are associated and presented in the form of a timeline, aiming to directly and easily locate an App's behavior throughout the app's lifecycle by dragging the timeline. With the help of Hooke, we found dozens of privacy leak issues hidden in malicious Apps and third-party SDKs.﻿

Link to Companies github: https://github.com/bytedance
Closest repo for this tool: https://github.com/bytedance/android-inline-hook
</details>

<details>
  <summary>GoTestWAF - well-known open-source WAF tester now supports API security hacking</summary>
  
GoTestWAF is a well-known open-source WAF testing tool which supports a wide range of attacks, bypassing techniques, data encoding formats, and protocols, including legacy web, REST, WebSocket, gRPC, and more.

With this major update, the tool now supports Swagger/OpenAPI-based scanning and becomes the first open-source testing tool available for API security solutions.
  
https://github.com/wallarm/gotestwaf 
</details>

<details>
  <summary>FireTail - inline API security checking</summary>

FireTail sits on top of popular open source frameworks for building web services and APIs, like OpenAPI/Swagger, Express and Rails, and then provides in-line security processing of the API calls. FireTail checks for (in sequential order):
1. API call is hitting valid route using a valid method. This allows for a zero-trust, declarative API structure, with proper error handling at the HTTP layer.
2. Inspection of authentication token. Does the API expect a JWT, application-issued API key or other? FireTail will check whether a valid token of the correct type is present.
3. Payload inspection. FireTail will look for and fail invalid queries. 

INFO:No links yet
Twitter of presentator: https://twitter.com/halffinn
</details>

<details>
  <summary>Faceless - Deepfake detection</summary>

Faceless is a deepfake detection system.

The proposed deepfake detection model is based on the EfficientNet structure with some customizations. It is hoped that an approachable solution could remind Internet users to stay secure against fake contents and counter the emergence of deepfakes.
The deepfake dataset were used in the final model is Celeb-DF
 
https://github.com/ManhNho/Faceless  
</details>

<details>
  <summary>CASPR - Code Trust Audit Framework</summary>

With CASPR, we are addressing the Supply Chain Attacks by Left Shifting the code signing process.
CASPR aims to provide simple scripts and services architecture to ensure all code changes in an organization are signed by trusted keys; trustability of these keys should be instantly verifiable every time the code changes are consumed. It also makes the auditing and accountability of code-changes easier and cryptographically verifiable, leaving no scope for malicious actors to sneak in untrusted code at any point in the Software Development Life Cycle.

INFO: No links yet
  
</details>

<details>
  <summary>CANalyse (2.0): A vehicle network analysis and attack tool.</summary>
  
A prerequisite to using telegram option of this tool is that the Hardware implant is already installed in the car and capable of communicating with the Network inside the vehicle. Also, the library requiremnt are satisfied.

Let's assume we have a car in which we have connected with USBtin(or user choice) which is connected to Raspberry pi (or any linux machine of userchoice) and the pi can communicate on the internet.
LInk to USBtin - https://www.fischl.de/usbtin/

What is CANalyse?

Canalyse uses python-can library to sniff vehicle network packets and analyze the gathered information and uses the analyzed information to command & control certain functions of the car.

CANalyse is a software tool built to analyze the log files in a creative powerful way to find out unique data sets automatically and able to connect to simple interfaces such as Telegram. Basically, while using this tool you can provide your bot-ID and be able to use the tool over the internet through telegram.

canalyse can be installed inside a raspberry-PI, it is made to analyse log files in a creative way and also made to exploit the vehicle through a telegram bot by recording and analyzing the data logs.

https://github.com/KartheekLade/CANalyse
</details>

<details>
  <summary>ArcherySec - Manage and Automate your Vulnerability Assessment</summary>
  
ArcherySec is an open-source vulnerability assessment and automation tool which helps developers and pentesters to perform scans and manage vulnerabilities. ArcherySec uses popular open-source tools to perform comprehensive scanning for web applications and networks. It also performs web application dynamic authenticated scanning and covers the whole application by using selenium. The developers can also utilize the tool for the implementation of their DevOps CI/CD environment.

Overview of the tool
- Perform web and network vulnerability scanning using open-source tools.
- Correlates and collaborates all raw scans data, shows them in a consolidated manner.
- Multi-user role-based accounts admin, analyst & viewer
- Policy-based CI/CD integration
- Perform authenticated web scanning.
- Perform web application scanning using selenium.
- Vulnerability management.
- Enable REST APIs for developers to perform scanning and vulnerability management.
- JIRA Ticketing System.
- Periodic scans.
- Useful for DevOps teams for vulnerability management.

https://github.com/archerysec/archerysec
</details>

<details>
  <summary>Stratus Red Team, an Open-Source Adversary Emulation Tool for the Cloud</summary>
  
Stratus Red Team is an open-source project for adversary emulation and validation of threat detection in the cloud. It comes with a catalog of cloud-native attack techniques mapped to MITRE ATT&CK that you can easily detonate against a live cloud environment or Kubernetes cluster.

Stratus Red Team supports common AWS and Kubernetes attack techniques. You can point it at a live AWS account or Kubernetes cluster and easily detonate TTPs commonly used by offensive actors, without any prerequisite infrastructure or configuration needed. It helps you validate your threat detection end-to-end and even has a programmatic interface to integrate it with existing automation.
Stratus Red Team transparently leverages Terraform to provision the infrastructure required to detonate TTPs, and Go to perform the actual attacks. The TTPs it packages are opinionated: granular, threat-informed, and actionable for defenders.

https://github.com/DataDog/stratus-red-team
</details>

<details>
  <summary>Secureworks® Primary Refresh Token (PRT) viewer</summary>

Azure AD registered and joined devices use a device certificate and transport key to sign and decrypt communication between the device and Azure AD. The most important part of this is Primary Refresh Token (PRT) and an associated session key. The session key can be decrypted with the transport key and subsequent communication with the session key.
Secureworks® Primary Refresh Token (PRT) viewer automates the decryption process. Using the transport key exported from the target computer, it automatically decrypts the session key from the PRT authentication request response. With the decrypted session key, it decrypts subsequent requests/responses decrypted with the session key.
The tool enables monitoring the traffic between the target device and Azure AD in plaintext, allowing extracting keys, access tokens, and other secrets.
The tool is available as Burp Suite Extender and Fiddler Add-On.

Companies Github: https://github.com/secureworks
  
</details>

<details>
  <summary>Ox4Shell - Deobfuscate Log4Shell payloads with ease</summary>
  
Since the release of the Log4Shell vulnerability (CVE-2021-44228), many tools were created to obfuscate Log4Shell payloads, making the lives of security engineers a nightmare.

Threat actors tend to apply obfuscation techniques to their payloads for several reasons. Most security protection tools, such as web application firewalls (WAFs), rely on rules to match malicious patterns. By using obfuscated payloads, threat actors are able to circumvent the rules logic and bypass security measures. Moreover, obfuscated payloads increase analysis complexity and, depending upon the degree of obfuscation, can also prevent them from being reverse-engineered.

Decoding and analyzing obfuscated payloads is time-consuming and often results in inaccurate data. However, doing so is crucial for understanding attackers' intentions.

We believe that security teams around the world can benefit from using Ox4Shell to dramatically reduce their analysis time. To help the security community, we have decided to release Ox4Shell - a payload deobfuscation tool that would make your life much easier.

https://github.com/ox-eye/Ox4Shell  
</details>

<details>
  <summary>Makes: A tool for avoiding supply chain attacks</summary>
  
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

https://github.com/fluidattacks/makes 
</details>

<details>
  <summary>LATMA - lateral movement analyzer</summary>
  
LATMA is a tool for offline detection and investigation of lateral movement attack based on AD event logs. The tool assists security teams to overcome the main challenges:

Data collection and preparation: in theory, event logs are an available data source to look for authentication anomalies. In practice, however, the source and destination machines are not represented in the same manner (hostname vs. IP), which prevents the ability to directly detect movement of a user account across different machines. LATMA conforms the representation of the source and destination machines, making the even log ready for analysis which is the tool's primary objectives.

Data analysis: LATMA scans the even data, looking for authentication patterns we have learned to be associated with lateral movement. For example, a chain of authentications where a single account logs from machine A to machine B and consecutively from machine B to C. Another example is what we call White-Cane in which an account logs from a single source to multiple destinations one after the other. The patterns LATMA searches for are based on our analysis of attacks in the wild, as well as on novel detection algorithm we have developed.

LATMA can be used in any environment where Kerberos and NTLM auditing is enabled, making it an easy and useful tool to any security professionals that handle an Active Directory environment. Offline analysis of authentications, while not real-time, is an efficient method to hunt for active lateral movement that goes under the radar and can provide the means to contain it before it reaches its objectives.

INFO: No links yet  
</details>

<details>
  <summary>AzureGoat : A Damn Vulnerable Azure Infrastructure</summary>
  
Microsoft Azure cloud has become the second-largest vendor by market share in the cloud infrastructure providers (as per multiple reports), just behind AWS. There are numerous tools and vulnerable applications available for AWS for the security professional to perform attack/defense practices, but it is not the case with Azure. There are far fewer options available to the community. AzureGoat is our attempt to shorten this gap.

In this talk, we will be introducing AzureGoat, a vulnerable by design infrastructure on the Azure cloud environment. AzureGoat will allow a user to do the following:

- Explore a vulnerable infrastructure hosted on an Azure account
- Exploring different ways to get a foothold into the environment, e.g., vulnerable web app, exposed endpoint, attached MSI
- Learn and practice different attacks by leveraging misconfigured Azure components like Virtual Machines, Storage Accounts, App Services, Databases, etc.
- Abusing Azure AD roles and permissions
- Auditing and fixing misconfiguration in IaC
- Redeploying the fixed/patched infrastructure

The user will be able to deploy AzureGoat on their Azure account using a pre-created Docker image and scripts. Once deployed, the AzureGoat can be used for target practice and be conveniently deleted later.

All the code and deployment scripts will be made open-source after the talk.

https://github.com/ine-labs/AzureGoat 
</details>

<details>
  <summary>Automating Fuzzable Target Discovery with Static Analysis</summary>
 
Vulnerability researchers conducting security assessments on software will often harness the capabilities of coverage-guided fuzzing through powerful tools like AFL++ and libFuzzer. This is important as it automates the bughunting process and reveals exploitable conditions in targets quickly. However, when encountering large and complex codebases or closed-source binaries, researchers have to painstakingly dedicate time to manually audit and reverse engineer them to identify functions where fuzzing-based exploration can be useful.

Fuzzable is a framework that integrates both with C/C++ source code and binaries to assist vulnerability researchers in identifying function targets that are viable for fuzzing. This is done by applying several static analysis-based heuristics to pinpoint risky behaviors in the software and the functions that executes them. Researchers can then utilize the framework to generate basic harness templates, which can then be used to hunt for vulnerabilities, or to be integrated as part of a continuous fuzzing pipeline, such as Google's oss-fuzz.

In addition to running as a standalone tool, Fuzzable is also integrated as a plugin for Binary Ninja, with support for other disassembly backends being developed.

https://github.com/ex0dus-0x/fuzzable  
</details>

<details>
  <summary>Unleash Purple Knight: Fend Off Invaders Lurking in Your Active Directory</summary>

Purple Knight is a free Active Directory (AD) and Azure AD security assessment tool developed by Semperis identity security experts that has been downloaded by 5,000+ users since its first release in spring 2021. Purple Knight runs as a standalone utility that queries the AD environment and performs a set of tests against many aspects of AD's security posture, including AD Delegation, account security, AD Infrastructure security, Group Policy security, and Kerberos security. The tool scans for indicators of exposure (IOEs) and indicators of compromise (IOCs). Each security indicator is mapped to security frameworks such as MITRE ATT&CK and the French National Agency for the Security of Information Systems (ANSII).

Purple Knight produces a report that includes an overall score, scores in individual categories, and prioritized guidance from identity security experts that serves as a roadmap for improving overall security posture. The report includes an explanation of what aspects of the indicator were evaluated and the likelihood that the exposure will compromise AD.

Purple Knight is continuously updated to address new security indicators based on original research and in response to emerging threats. As an example, the Purple Knight team released indicators for the Windows Print Spooler service and PetitPotam flaws within days after their discovery. New updates to be demonstrated at Arsenal include:
• Newest in the 100+ indicators of exposure (IOEs) and indicators of compromise (IOCs)
• New Azure Active Directory security indicators
• Post-breach forensics capabilities that enable incident response teams to specify an attack window to accelerate remediation

Purple Knight continuously evolves through feedback from an engaged community of users on the Purple Knight Slack channel and through individual outreach to users who communicate directly with the product teams.  

https://www.purple-knight.com/  
</details>



<details>
  <summary>The Mathematical Mesh</summary>
  
The Mathematical Mesh is a Threshold Key Infrastructure that allows cryptographic applications to provide effortless security. Threshold key generation and threshold key agreement are used to provide end-to-end security of data in transmission and data at rest without requiring any additional user interactions.

Once a device is connected to a user's personal Mesh through a simple, one-time configuration step, all private key and credential management functions are automated. Devices may be provisioned with private keys required to support applications such as OpenPGP, S/MIME and SSH according to intended use of that device.

https://github.com/hallambaker/Mathematical-Mesh
</details>

<details>
  <summary>Streamlining and Automating Threat Hunting With Kestrel</summary>
 
Kestrel is a rapidly evolving threat hunting language designed to accelerate cyber threat hunting by providing a layer of abstraction to build reusable, composable, and shareable hunt-flow. It brings two key innovations to the security community: (i) a composable way expressing threat hypothesis development over entity-relational data abstractions, and (ii) an open-source language runtime generating and executing repetitive hunt instructions on local hunting sites, remote data sources, and in the cloud. Kestrel significantly simplifies hunting and sharing by creating a standard way to encode a single hunt step, chain multiple hunt steps, and fork/merge hunt-flows to develop threat hypothesis. It focuses threat hunters on the reusable business logic of hunt, other than writing multiple endpoint query languages, understanding incompatible query results, and converting analytics and visualization for each specific hunt.

This arsenal session will showcase the latest language development and community opportunities for Kestrel. We will start with powerful federated data retrieval using the Structured Threat Information eXpression (STIX) standard and STIX-shifter and lift the results into an entity-relational data model. Then we will showcase analytic hunt steps besides data retrieval steps, compare the new Python analytics interface with the container-based interface, and execute analytics for context enrichment, de-obfuscation, and visualization. After creating, executing, saving, and re-executing huntbooks, we will connect Kestrel with the Open Command and Control (OpenC2) standard to respond to "investigate" commands and automate huntbook execution, data gathering, false positive elimination, and comprehensive analysis.

Making it ready to try by the audience, we will demonstrate live hunts in Jupyter Notebooks launched and executed in a Binder cloud sandbox as part of a purple team exercise. At the end of the session, we will introduce the kestrel-huntbook repo for people to reuse existing huntbooks and share their hunting knowledge with their colleagues and other hunters in the community.

https://github.com/opencybersecurityalliance/kestrel-lang
</details>

<details>
  <summary>Sandboxing in Linux with zero lines of code</summary>

Linux seccomp is a simple, yet powerful tool to sandbox running processes and significantly decrease potential damage in case the application code gets exploited. It provides fine-grained controls for the process to declare what it can and can't do in advance and in most cases has zero performance overhead.

The only disadvantage: to utilize this framework, application developers have to explicitly add sandboxing code to their projects and developers usually either delay this or omit completely as their main focus is mostly on the functionality of the code rather than security. Moreover, the seccomp security model is based around system calls, but many developers, writing their code in high-level programming languages and frameworks, either have little knowledge to no experience with syscalls or just don't have easy-to-use seccomp abstractions or libraries for their frameworks.

All this makes seccomp not widely adopted—but what if there was a way to easily sandbox any application in any programming language without writing a single line of code? This presentation discusses potential approaches with their pros and cons.  
  
https://github.com/seccomp/libseccomp
</details>

<details>
  <summary>Protecting your Crypto Asset against Malicious JS Phishing</summary>
  
Cryptocurrencies and NFT are taking over with predictions of 90% of the population holding at least one of them by the end of the decade. Users that want to facilitate these new assets, trade them and sell them typically do that using wallets, and in particular hot wallets that are easy-to-use. The most popular hot wallets today (e.g., MetaMask) are browser based and are thus vulnerable to phishing and scams made possible through malicious JavaScript, such as a recent campaign carried out by the Lazarus group which resulted in more than 400M$ worth of stolen cryptocurrencies.

We release our internal tool used by the Security Operation and the research at Akamai to scan the JS from any website.
It includes a Python recursive crawler that extracts every JS from any domain (written within the HTML or imported), analyzes it with a model and heuristics - that we provide -, and brings metadata ( from VT, publicwww…) It finally gives a score to every piece of code running on any URL of a specified domain.
The code works also as a Web App and exposes a REST API as well.

We will finish by presenting some real detection we caught with this tool and explaining them.

https://github.com/akamai/js_api
</details>

<details>
  <summary>FACT 4.0</summary>

Analyzing Firmware specifically to identify potential vulnerabilities is a common activity for security analysts, pentesters, researchers or engineers concerned with embedded devices such as in IoT. FACT offers an automated and usable platform to gain an immediate overview of potential vulnerabilities based on the firmware of a device and supercharges the process of finding deep vulnerabilities.

For this FACT automatically breaks down a firmware into its components, analyzes all components and summarizes the results. The analysis can then be perused in the desired amount of detail using either the responsive web application or a REST API.

The offered analyses include a list of included software and libraries, a matching of said software to CVE databases, identification of hard-coded credentials, private key material and weak configuration among others. FACT also applies source and binary code analysis to identify (possibly exploitable) bugs in the components and offers a large amount of meta data for further manual analysis.

A focus of recent development has been to offer more information regarding interdependencies between firmware components to ease the identification of data flow inside a firmware. This allows quickly grading the risk involved with uncovered vulnerabilities or configuration flaws by finding possible attack vectors concerning given component.

Finally, FACT offers multiple ways to collect and fuse analysis results, such as firmware comparison, advanced search options including regular expression on binary components and an integrated statistics module.  

https://github.com/fkie-cad/FACT_core
</details>

<details>
  <summary>Defaultinator: An Open Source Search Tool for Default Credentials</summary>
  
Have you ever had to Google around trying to find a default password for a router? Are you sick of combing through user manuals just to find admin:admin buried on page 37. Then it's time you tried Defaultinator. This newly released tool is a repository for default credentials made searchable via API or the intuitive web interface. Why would someone make such a tool? Why, I'm so glad you asked!

Static device passwords are not only Really Bad, they are sometimes illegal. Yet legacy or poorly secured IoT devices still often contain default or hardcoded passwords. It's hard to know if you have default passwords in your environment, but this tool is here to help you find them. Or maybe you are on a Red Team engagement and want to audit for CWE-798 (Use of Hard-coded Credentials). Defaultinator has your back.

In this talk, I'll cover how default passwords contribute to the spread of malware, how common it is to see them used in brute force attacks 'in the wild', and how a tool like Defaultinator can help you identify them and remove them from your own environment.

https://defaultinator.com/
</details>

<details>
  <summary>Adhrit: Android Security Suite</summary>
  
Adhrit is an open-source Android application security analysis suite. The tool is an effort to find an efficient solution to all the needs of mobile security testing and automation. Adhrit has been built with a focus on flexibility and modularization. It currently uses the Ghera benchmarks to identify vulnerable code patterns in the bytecode. Apart from bytecode scanning, Adhrit can also identify hardcoded secrets within Android applications. The tool also comes with a built-in integration to popular software like Jira and Slack which can be configured to automate and streamline.

https://github.com/abhi-r3v0/Adhrit 
</details>

<details>
  <summary>smarX - Solidity Smart Contract Vulnerability Analyzer</summary>
  
 Smart contracts are magical because they execute themselves once the predefined conditions are met. Unfortunately, it is easier than we would like to admit to lose funds or ownership of our contracts (either to a malicious actor or by accidentally locking everything inside). To avoid that, smarX scans your smart contracts, alerts for discovered vulnerabilities, and suggests remediations.

By using static code analysis for Solidity smart contracts, smarX helps developers find and mitigate vulnerabilities before deploying their smart contracts to the blockchain. smarX scans the code with out-of-the-box rules created by us and rules contributed by the community. In addition, it will allow developers and security engineers to easily create customized rules, allowing them to inspect their code for specific issues of interest. The rules are aimed to be short and readable, so it'll be easy for newcomers to add their own.

The Solidity parser and the sets of rules will both be released and open-sourced during Black Hat's Arsenal.

Key Features:
1. Vulnerability analysis with low FP/FN rates
2. Identification of the vulnerable line
3. Can be used as an IDE Plugin
4. Integrates with continuous integration.
5. Supported by Checkmarx, one of the leaders of the SAST industry

INFO: No links yet
</details>

<details>
  <summary>Objective-See's Mac Security Tools</summary>
  
Objective-See's security tools are free, open-source, and provide a myriad of ways to protect macOS systems from hackers, malware, or even commercial applications that behave poorly!

In this demo, will cover our most popular tools including, LuLu, OverSight, BlockBlock and more.

We'll also highlight various command-line tools (that leverage Apple's new Endpoint Security Framework) designed to facilitate both malware analysis and macOS spelunking.
  
https://github.com/objective-see
</details>

<details>
  <summary>EMBA – Open-Source Firmware Security Testing</summary>
  
IoT (Internet of Things) and OT (Operational Technology) are the current buzzwords for networked devices on which our modern society is based on. In this area, the used operating systems are summarized with the term firmware. The devices themselves, also called embedded devices, are essential in the private and industrial environments as well as in the so-called critical infrastructure.
Penetration testing of these systems is quite complex as we have to deal with different architectures, optimized operating systems and special protocols. EMBA is an open-source firmware analyzer with the goal to simplify and optimize the complex task of firmware security analysis. EMBA supports the penetration tester with the automated detection of 1-day vulnerabilities on binary level. This goes far beyond the plain CVE detection: With EMBA you always know which public exploits are available for the target firmware. Besides the detection of already known vulnerabilities, EMBA also supports the tester on the next 0-day. For this, EMBA identifies critical binary functions, protection mechanisms and services with network behavior on a binary level. There are many other features built into EMBA, such as fully automated firmware extraction, finding file system vulnerabilities, hard-coded credentials, and more.

EMBA is the open-source firmware scanner, created by penetration testers for penetration testers.

https://github.com/e-m-b-a/emba
</details>

<details>
  <summary>Detecting Linux Kernel Rootkits with Tracee</summary>
  
Linux Kernel Rootkits is an advanced and fascinating topic in cyber security. These tools are stealthy and evasive by design and often target the lower levels of the OS, unfortunately there aren't many solid security tools that can provide an extensive visibility to detect these kinds of tools.
Tracee is a Runtime Security and forensics tool for Linux, utilizing eBPF technology to trace systems and applications at runtime, analyze collected events to detect suspicious behavioral patterns, and capture forensics artifacts.

Tracee was presented in BH EU 2020 and BH USA 2021. Thus far we have presented Tracee-ebpf and spoke about its passive capabilities to collect OS events based on given filters, and Tracee-rules, which is the runtime security detection engine. But Tracee has another capability to safely interact with the Linux kernel, which grants Tracee even more superpowers.

Tracee was designed to provide observability on events in running containers. It was released in 2019 as an OSS project, allowing practitioners and researchers to benefit from its capabilities. Now, Tracee has greatly evolved, adding more robust and advanced capabilities. Tracee is a runtime security and forensics tool for Linux, built to address common Linux security issues.

For references see:
https://blog.aquasec.com/ebpf-container-tracing-malware-detection
https://blog.aquasec.com/advanced-persistent-threat-techniques-container-attacks  

https://github.com/aquasecurity/tracee
</details>

<details>
  <summary>CQPenetrationTesting Toolkit: Powerful Toolset That All Pentesters Want to Have</summary>

CQ Penetration Testing Toolkit supports you in performing complex penetration tests as well as shows the ways to use them, and the situations in which they apply. It guides you through the process of gathering intel about network, workstations, and servers. Common technics for antimalware avoidance and bypass, lateral movement, and credential harvesting. The toolkit allows also for decrypting RSA keys and EFS protected files as well as blobs and objects protected by DPAPI and DPAPI-NG. This powerful toolkit is useful for those who are interested in penetration testing and professionals engaged in pen-testing working in the areas of database, system, network, or application administration. Among published presented tools are CQARPSpoofer, CQCat, CQDPAPIBlobDecrypter, CQMasterKeyDecrypt, CQReverseShellGen, and many more.

https://github.com/BlackDiverX/cqtools
</details>

<details>
  <summary></summary>
  
  
</details>

<details>
  <summary></summary>
  
  
</details>

<details>
  <summary></summary>
  
  
</details>

<details>
  <summary></summary>
  
  
</details>

<details>
  <summary></summary>
  
  
</details>

<details>
  <summary></summary>
  
  
</details>

<details>
  <summary></summary>
  
  
</details>

<details>
  <summary></summary>
  
  
</details>

# BlackHat Arsenal 2023 Asia

Links to the repositories or other stuff of the BlackHat Asia 2023

<details>
  <summary>AiCEF: An AI-powered Cyber Exercise Content Generation Framework</summary>
The core idea of AiCEF, is to harness the intelligence that is available from online and MISP reports, as well as threat groups' activities, arsenal etc., from, e.g., MITRE, to create relevant and timely cybersecurity exercises. To this end, we have developed a specialised ontology called Cyber Exercise Scenario Ontology (CESO), which extends STIX [2]. The core idea is to map reports; both from online resources and MISP, via a common ontology to graphs. This way, we abstract the events from the reports in a machine-readable form. The produced graphs can be infused with additional intelligence, e.g. the threat actor profile from MITRE, also mapped in our ontology. While this may fill gaps that would be missing from a report, one can also manipulate the graph to create custom and unique models. Finally, we exploit transformer-based language models like GPT to convert the graph into text that can serve as the scenario of a cybersecurity exercise.
We have tested and validated AiCEF with a group of experts in cybersecurity exercises, and the results clearly show that AiCEF significantly augments the capabilities in creating timely and relevant cybersecurity exercises in terms of both quality and time.

Paper: https://link.springer.com/article/10.1007/s10207-023-00693-z  
</details>

<details>
  <summary>APKHunt | OWASP MASVS Static Analyzer</summary>
  
  APKHunt is a comprehensive static code analysis tool for Android apps that is based on the OWASP MASVAS framework. The OWASP MASVS (Mobile Application Security Verification Standard) is the industry standard for mobile app security. APKHunt is intended primarily for mobile app developers and security testers, but it can be used by anyone to identify and address potential security vulnerabilities in their code.

With APKHunt, mobile software architects or developers can conduct thorough code reviews to ensure the security and integrity of their mobile applications, while security testers can use the tool to confirm the completeness and consistency of their test results. Whether you're a developer looking to build secure apps or an infosec tester charged with ensuring their security, APKHunt can be an invaluable resource for your work.

Key features of APKHunt:
- Scan coverage: Covers most of the SAST (Static Application Security Testing) related test cases of the OWASP MASVS framework.
- Optimised scanning: Specific rules are designed to check for particular security sinks, resulting in an almost accurate scanning process.
- Low false-positive rate: Designed to pinpoint and highlight the exact location of potential vulnerabilities in the source code.
- Output format: Results are provided in a TXT file format for easy readability for end-users.

Current Limitation:
- Supporting OS/Language: Capable of scanning the source code of an android APK file and is only supported on Linux environments.

Upcoming Features:
- Scanning of multiple APK files at the same time
- More output format such as HTML
- Integration with third-party tools

Github: https://github.com/Cyber-Buddy/APKHunt
  
</details>

<details>
  <summary>CQ PrivilegeEscalation Toolkit: Effective Tools for Windows Privilege Escalation Gamers</summary>

CQURE PE Toolkit is focused on Windows Privilege Escalation tactics and techniques created to help to improve every privilege escalation game. This toolkit guides you through the process of exploiting a bug or design flaw in an operating system or software to gain elevated privileges to resources that are normally highly protected. Once you know what to look for and what to ignore, Privilege Escalation will become so much easier. This powerful toolkit is tremendously useful for those who are interested in penetration testing and professionals engaged in pen-testing who work in the areas of databases, systems, networks, or application administration.

Website: https://cqureacademy.com/blog/hacks/sysmon

Toolkit with sheets from BlackHat2019 which expains the tools
https://github.com/BlackDiverX/cqtools
</details>

<details>
  <summary>Interactive Kubernetes Security Learning Playground - Kubernetes Goat</summary>

Kubernetes Goat is an interactive Kubernetes security learning playground. It has intentionally vulnerable by design scenarios to showcase the common misconfigurations, real-world vulnerabilities, and security issues in Kubernetes clusters, containers, and cloud native environments.

It's tough to learn and understand Kubernetes security safely, practically, and efficiently. So here we come to solve this problem not only for security researchers but also to showcase how we can leverage it for attackers, defenders, developers, DevOps teams, and anyone interested in learning Kubernetes security. We are also helping products & vendors to showcase their product or tool's effectiveness by using these playground scenarios and also help them to use this to educate their customers and organizations. This project is a place to share knowledge with the community in well-documented quality content in hands-on scenario approaches.

Github: https://github.com/madhuakula/kubernetes-goat
</details>

<details>
  <summary>MemTracer: Hunting for Forensic Artifacts in Memory</summary>
  MemTracer is a tool that offers live memory analysis capabilities, allowing digital forensic practitioners to discover and investigate stealthy attack traces hidden in memory.

Advanced persistence threat (APT) adversaries use stealthy attack tactics that only leave volatile short-lived memory evidence. The reflective Dynamic-Link Library (DLL) load technique is considered one of the stealthiest attack techniques. Reflective DLL load allows adversaries to load malicious code directly into memory, rather than loading a file from the disk. Thus, reflective DLL load leaves no digital evidence present on the disk. The malicious DLL continues to execute as long as the compromised process is running. Terminating a compromised process leads to the removal of the malicious DLL from memory, and the release of the memory region back to the pool for reallocation. Therefore, memory needs to be examined periodically in order to detect the existence of a malicious DLL that loaded reflectively into memory. 

Loading DLL reflectively produces an unusual memory region’s characteristics that can indicate its existence. The MemTracer tool was developed to efficiently scan memory regions to detect reflective DLL loading symptoms. Mainly, MemTracer aims to detect native .NET framework DLLs that are loaded reflectively. Additionally, MemTracer provides the ability to search for a specific loaded DLL by name, which can retrieve the list of processes that have abnormally loaded the specified module for further investigation.
  
  https://github.com/kristopher-pellizzi/MemTrace
</details>

<details>
  <summary>Mr. SIP: SIP-Based Audit and Attack Tool</summary>
  
  Mr.SIP is a functional SIP-based penetration testing tool. It is the most comprehensive offensive VoIP security tool ever developed. Mr.SIP is developed to assist security experts and system administrators who want to perform security tests for VoIP systems and to measure and evaluate security risks. It quickly discovers all VoIP components and services in a network topology along with vendor, brand, and version information, and detects current vulnerabilities, and configuration errors. It provides an environment to assist in performing advanced attacks to simulate abuse of detected vulnerabilities. It detects SIP components and existing users on the network, intervenes, filters, and manipulates call information, develops various DoS attacks, including status-controlled, breaks user passwords, and can test the server system by sending irregular messages.

In the current state, Mr.SIP comprises 9 sub-modules named SIP-NES (network scanner), SIP-ENUM (enumerator), SIP-DAS (DoS attack simulator), SIP-ASP (attack scenario player), SIP-EVA (eavesdropper), SIP-SIM (signaling manipulator), SIP-CRACK (cracker), SIP-SNIFF (sniffer), and SIP-FUZZ (fuzzer).

https://github.com/meliht/Mr.SIP
  
</details>

<details>
  <summary>Nightingale: Docker for Pentesters</summary>
  
Docker containerization is the most powerful technology in the current market so I came with the idea to develop Docker images for Pentesters.

Nightingale contains all the required famous tools that will be required to the pentester at the time of Penetration Testing. This docker image has the base support of Debian and it is completely platform Independent.

You can either create a docker image in your local host machine or you can directly pull the docker images from the docker hub itself.

https://github.com/RAJANAGORI/Nightingale
</details>

<details>
  <summary>Osiris-Framework: A Scalable Tool for Penetration Testing and Vulnerability Assessment on Cross-Platform Systems</summary>
  
Abstract—Osiris-Framework V1.337 is an open-source project designed to assist security researchers in penetration testing and vulnerability assessment exercises through unique features such as 0-days and helpers, custom-made modules, and the ability to provide valuable information about vulnerabilities in a specific target. Additionally, the framework can be executed in multi-platform systems which allows security researchers to perform audits from geographically widespread locations.

Github: https://github.com/osiris-framework/osiris-framework
  
</details>

<details>
  <summary>Slips: Free software machine learning tool for Network Intrusion Prevention System</summary>
  
 Slips is the first free software, behavioral-based, intrusion prevention system to use machine learning to detect attacks in the network. It is a modular system that profiles the behavior of devices and performs detections in time windows. Slips' modules detect a range of attacks both to and from the protected devices.

Slips detect attacks to and from devices protecting your network but also focusing on infected computers. All the analyses are reevaluated in time windows so computers can be unblocked if they are cleaned. Avoiding permanent detections when the risk is gone.

Slips manages Threat Intelligence feeds (44 external feeds, including our own), the enrichment with WHOIS/ASN/geo location/mac vendors. Allowing it to detect MITM attacks, scans, exfiltration, port scans, long connections, data uploads, unknown ports, connections without DNS, malicious JA3/JA3S, TLS certificates, etc.

An LSTM neural network detects C&C channels, a Random Forest is used to detect attacks on flows, and anomaly detection methods are used on the traffic. A final ML ensembling algorithm is used for blocking decisions and alert generation.

Slips reads packets from an interface, PCAPs, Suricata, Zeek, Argus and Nfdump. It generates alerts in text, json, and using the STIX/TAXII protocol, sending to CESNET servers using IDEA0 format, or to Slack.

Slips is the first IDS to use its own local P2P network to find other Slips peers and exchange data about detection using trust models that are resilient to adversarial peers.

The Kalipso Node.js and a Web interface allows the analysts to see the profiles' behaviors and detections performed by Slips modules directly in the console. Kalipso displays the flows of each profile and time window and compares those connections in charts/bars. It also summarizes the whois/asn/geocountry information for each IP in your traffic.

 https://github.com/stratosphereips/StratosphereLinuxIPS
</details>
StegoWiper  

<details>
  <summary>StegoWiper+: A Powerful and Flexible Active Attack for Disrupting Stegomalware and Advanced Stegography</summary>
  
  Over the last 10 years, many threat groups have employed stegomalware or other steganography-based techniques to attack organizations from all sectors and in all regions of the world. Some examples are: APT15/Vixen Panda, APT23/Tropic Trooper, APT29/Cozy Bear, APT32/OceanLotus, APT34/OilRig, APT37/ScarCruft, APT38/Lazarus Group, Duqu Group, Turla, Vawtrack, Powload, Lokibot, Ursnif, IceID, etc.Our research shows that most groups are employing very simple techniques (at least from an academic perspective) and known tools to circumvent perimeter defenses, although more advanced groups are also using steganography to hide C&C communication and data exfiltration. We argue that this lack of sophistication is not due to the lack of knowledge in steganography (some APTs have already experimented with advanced algorithms) but simply because organizations are not able to defend themselves, even against the simplest steganography techniques.

During the demonstration we will show the practical limitations of applying existing automated steganalysis techniques for companies that want to prevent infections or information theft by these threat actors. For this reason, we have created stegoWiper, a tool to blindly disrupt any image-based stegomalware, attacking the weakest point of all steganography algorithms: their robustness. We'll show that it is capable of disrupting all steganography techniques and tools (Invoke-PSImage, F5, Steghide, openstego, ...) employed nowadays. In fact, the more sophisticated a steganography technique is, the more disruption stegoWiper produces. Moreover, our active attack allows us to disrupt any steganography payload from all the images exchanged by an organization by means of a web proxy ICAP (Internet Content Adaptation Protocol) service, in real time and without having to identify which images contain hidden data first.

After our presentation at BlackHat USA 2022 Arsenal we have been working on supporting, disrupting, state-of-the-art advanced algorithms available in the academic literature, based on matrix encryption, wet-papers, etc. (e.g. Hill, J-Uniward, Hugo). Especially we have paid attention to the YASS algorithm (https://pboueke.github.io/CryptoStego/) resistant to numerous active attacks and commercial CDR-type software. Finally our tool is able to defeat them.

Github: https://github.com/mindcrypt/stegowiper  
</details>

<details>
  <summary>Unprotect Project: Malware Evasion Techniques</summary>

Malware evasion consists of techniques used by malware to bypass security in place, circumvent automated and static analysis as well as avoiding detection and harden reverse engineering. There is a broad specter of techniques that can be used. In this talk we will review the history of malware evasion techniques, understand the latest trends currently used by threat actors and bolster your security analysis skills by getting more knowledge about evasion mechanisms.

We will present the latest major update of the Unprotect Project an open-source documentation about malware evasion techniques. The goal will be to present the project and see how we can leverage it for use cases, including threat intelligence, malware analysis, strengthen security, train people, and extend the Mitre ATT&CK matrix. Over the years it has become a well renowned place for security researchers. During this talk we will review some of the most important update.

This presentation can benefit both Blue and Red Team as it will provide knowledge and information on how malware can bypass your security in place and stay under the radar. You will learn about the intrinsic mechanisms used by attackers to compromise you without you even realizing it!

Homepage: https://unprotect.it/
</details>

<details>
  <summary>AADInternals: The Swiss Army Knife for Azure AD & M365</summary>
  
 AADInternals is a popular attacking and administration toolkit for Azure Active Directory and Microsoft 365, used by red and blue teamers worldwide. The toolkit is written in PowerShell, making it easy to install and use by anyone familiar with the Microsoft ecosystem. It has been downloaded from PowerShell gallery over 20,000 times and it is listed in MITRE ATT&CK tools.

With AADInternals, one can create backdoors, perform elevation of privilege and denial-of-service attacks, extract information, and even bypass multi-factor authentication (MFA).

Join this session to see in action the research results conducted during the past three years, including a new technique to extract AD FS signing certificates remotely, exporting certificates of AAD joined devices, gathering OSINT, and more!

 Documentation: https://aadinternals.com/aadinternals/
 
 https://github.com/Gerenios/AADInternals
</details>

<details>
  <summary>N3XT G3N WAF 2.0</summary>

Previously, we introduced N3XT G3N WAF (NGWAF) 1.0 at BHUSA 2022. The novel WAF 3.0 tool that seeks to relieve complex and difficult WAF detection mechanism with detection utilising a Sequential Neural Network (SNN) and traps attackers through a custom honeypotted environment. These assets are all dockerised for scalability.

However, further experiments have proven that a SNN may not be the most optimal when it comes down to contextualised defence as it processes information in a step by step and sequential manner. It gets relatively cumbersome and ineffective detecting chained or contexualised attacks. Both of which are extremely common in today's attacks.

Thus, we took another approach by swapping out our "brains". We revamped the SNN and went with a Recurrent Neural Network (RNN). The RNN is a much better choice for contextualised defense as the output of each layer is fed back as the input of the same layer. Thus, this allows the network to maintain a "memory" of the data it has processed. Our latest model is a RNN with a bi-directional LSTM module, it has an accuracy of 0.995 and a f1 score of 0.993.

We have also upgraded NGWAF's scalability in model deployment, model maintenance and the overall detection pipeline. This is all done with cloudifying the operations of the entire Machine Learning detection module. As compared to version 1.0 where users have to install and run the entire framework on their local system, NGWAF 2.0 has employed Infrastructure-as-Code (IaC) scripts, which auto-deploys the machine learning model's training & maintenance pipeline onto AWS resources (Sagemaker). The detection module has also been shifted from local deployment to AWS Sagemaker where we are able to standardise the hardware utilised for the ML model. This also allows further decoupling of the detection module from the rest of the system and allow for greater customisability.

BHUSA 2022 - Version 01: (https://www.blackhat.com/us-22/arsenal/schedule/index.html#nxt-gn-waf-ml-based-waf-with-retraining-and-detainment-through-honeypots-26609)

https://github.com/FA-PengFei/NGWAF
  
</details>

<details>
  <summary>reNgine: An Open-Source Automated Reconnaissance/Attack Surface Management tool</summary>

reNgine is an open-source automated reconnaissance framework, that helps quickly discover the attack surface using highly customizable and powerful scan engines. reNgine also comes with some of the most innovative features such as sub scans feature, configurable scan report (both reconnaissance and vulnerability pdf report), tools arsenal which allows updating preinstalled tools and their configurations, graphical distribution of assets, WHOIS identification, and tons of actionable insights such as most common vulnerability, most common CVE IDs, etc.

The most recent versions of reNgine make it more than just a recon tool!

reNgine has always aimed to fix the gap in the traditional recon tools and is probably a much better alternative for some of the commercial recon and vulnerability assessment tools.

https://github.com/yogeshojha/rengine
</details>

<details>
  <summary>Prediction System for Lateral Movement Based on ATT&CK Using Sysmon</summary>
 
 This tool converts Windows logs collected by Sysmon into MITER ATT&CK Technique and allows us to refer to attack types and progress based on the ATT&CK structure.
In a company network, when we detect that a device has been infected with malware, it is not easy to find other infected devices, and we consume a lot of human resources and time. With this tool, we can grasp the possibility of infection to other devices and the progress of attack using ATT&CK and statistical methods based on the Sysmon log.
Furthermore, this tool automatically converts aggregated Sysmon logs into ATT&CK Technique using Atomic Red Team's library. The converted information is visualized in a list format or colored in the ATT&CK Matrix.
It is beneficial when significant and chaotic logs can be transformed into a clear cybersecurity knowledge base format in a few moments. The tool is also helpful for real-world anomaly detection and cybersecurity learning.
We will provide this tool as a Web application and publish its source code on GitHub.

Not sure if this is the tool.
Atomic-Red-Team Github: https://github.com/redcanaryco/atomic-red-team 
  
</details>

<details>
  <summary>SquarePhish: Combining QR Codes and OAuth 2.0 Device Code Flow for Advanced Phishing Attacks</summary>
  
  SquarePhish is an advanced phishing tool that uses a technique combining the OAuth Device code authentication flow and QR codes.
  
  Github: https://github.com/secureworks/squarephish
</details>

<details>
  <summary>White Phoenix - Beating Intermittent Encryption</summary>
  
  Intermittent Encryption (aka Partial Encryption) is a new trend in the world of ransomware. It's been adopted by many notorious groups such as BlackCat Ransomware, Play Ransomware and more. Altogether, the groups using intermittent encryption have successfully targeted hundreds of organizations in 2022 alone. However, even though intermittent encryption has its advantages, it leaves much of the content of targeted files unencrypted. In this talk, we will demonstrate a tool that uses this limitation to recover valuable data, such as text and images from documents encrypted by these groups, allowing the victims to recover some of their lost data.
  
  Github: https://github.com/cyberark/White-Phoenix
  
</details>

<details>
  <summary>Faceless - Deepfake Detection with Faceless</summary>

Faceless is a deepfake detection system.

The proposed deepfake detection model is based on the EfficientNet structure with some customizations. It is hoped that an approachable solution could remind Internet users to stay secure against fake contents and counter the emergence of deepfakes.
The deepfake dataset were used in the final model is Celeb-DF
 
https://github.com/ManhNho/Faceless  
</details>

<details>
  <summary>CANalyse 2.0 : A Vehicle Network Analysis and Attack Tool</summary>
  
  CANalyse is a software tool built to analyse the log files in a creative powerful way to find out unique data sets automatically and inject the refined payload back into vehicle network. It can also connect to simple interfaces such as Telegram for remote control. Basically, while using this tool you can provide your bot-ID and be able to use the tool's inbuilt IDE over the internet through telegram.

  CANalyse uses python-can library to sniff vehicle network packets and analyse the gathered information and uses the analysed information to command & control certain functions of the vehicle. CANalyse can be installed inside a raspberry-PI, to exploit the vehicle through a telegram bot by recording and analysing the vehicle network.
  
  Github: https://github.com/KartheekLade/CANalyse
  
</details>

<details>
  <summary>Exegol</summary>
Exegol is a free and open-source pentesting environment made for professionals. It allows pentesters to conduct their engagements in a fast, effective, secure and flexible way. Exegol is a set of pre-configured and finely tuned docker images that can be used with a user-friendly Python wrapper to deploy dedicated and disposable environments in seconds.  

https://github.com/ThePorgs/Exegol
</details>

<details>
  <summary>SharpToken: Windows Token Stealing Expert</summary>
  
  During red team lateral movement, we often need to steal the permissions of other users. Under the defense of modern EDR, it is difficult for us to use Mimikatz to obtain other user permissions, and if the target user has no process alive, we have no way to use "OpenProcessToken" to steal Token.


  SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them. If you are a low-privileged service user, you can even use it to upgrade to "NT AUTHORITY\SYSTEM" privileges, and you can switch to the target user's desktop to do more without the target user's password. ..
  
 Github:  https://github.com/BeichenDream/SharpToken
  
</details>

<details>
  <summary>Backdoor Pony: Evaluating Backdoor Attacks and Defenses in Different Domains</summary>

Outsourced training and crowdsourced datasets lead to a new threat for deep
learning models: the backdoor attack. In this attack, the adversary inserts a
secret functionality in a model, activated through malicious inputs. Backdoor
attacks represent an active research area due to diverse settings where they
represent a real threat. Still, there is no framework to evaluate existing
attacks and defenses in different domains. Only a few toolboxes have been
implemented, but most of them focus on computer vision and are difficult
to use. To bridge this gap, we present Backdoor Pony, a framework for
evaluating attacks and defenses in different domains through a user-friendly
GUI.

Paper https://repository.tudelft.nl/islandora/object/uuid%3A53153995-a055-43a4-a6f6-05069eb19d3f

</details>

<details>
  <summary>DotDumper: Automatically Unpacking DotNet Based Malware</summary>
  
Analysts at corporations of any size face an ever-increasing amount of DotNet based malware. The malware comes in all shapes and forms, ranging from skiddish stealers all the way to nation state backed targeted malware. The underground market, along with public open-source tools, provide a plethora of ways to obfuscate and pack the malware. Unpacking malware is time consuming, difficult, and tedious, which poses a problem.

To counter this, DotDumper automatically dumps interesting artifacts during the malware’s execution, ranging from base64 decoded values to decrypted PE files. As such, the malware decrypts and executes the next stage, while DotDumper conveniently provides a copy of said decrypted stage. All this is done via a simple, compact, intuitive, and easy-to-use command-line interface.

Aside from the dumped artifacts, DotDumper provides an extensive log of the traced execution, based on managed hooks. For each hook, the log contains the original function name, arguments and their values, and the return value. Since DotDumper ensures that the original function is called, the malware’s execution continues as if it was executed normally, allowing the analyst to get as many stages from the sample as possible.

DotDumper can execute DotNet Framework executables, as well as dynamic link libraries, due to the fully-fledged reflective loader which is embedded. Any given function can be selected within a library, along with any required variables and their values, all easily accessible from DotDumper’s command-line interface.

DotDumper has proven to be effective in dealing with the renowned AgentTesla stealer or the WhisperGate Wiper loader, allowing an analyst to easily fetch the decrypted and unpacked in-memory only stages, thus decreasing up the time spent on unpacking, allowing for faster response to the given threat.

https://github.com/advanced-threat-research/DotDumper  
  
</details>

<details>
  <summary>GodPotato: As Long as You Have the ImpersonatePrivilege Permission, Then You are the SYSTEM!</summary>
Based on the history of Potato privilege escalation for 6 years, from the beginning of RottenPotato to the end of JuicyPotatoNG, I discovered a new technology by researching DCOM, which enables privilege escalation in Windows 2012 - Windows 2022, now as long as you have "ImpersonatePrivilege" permission. Then you are "NT AUTHORITY\SYSTEM", usually WEB services and database services have "ImpersonatePrivilege" permissions.
  
Potato privilege escalation is usually used when we obtain WEB/database privileges. We can elevate a service user with low privileges to "NT AUTHORITY\SYSTEM" privileges.
However, the historical Potato has no way to run on the latest Windows system. When I was researching DCOM, I found a new method that can perform privilege escalation. There are some defects in rpcss when dealing with oxid, and rpcss is a service that must be opened by the system. , so it can run on almost any Windows OS, I named it GodPotato

https://github.com/BeichenDream/GodPotato
  
</details>


<details>
  <summary>CureIAM: The Ultimate Solution to Least Privilege Principle Enforcement on GCP</summary>
  
  CureIAM is an easy-to-use, reliable, and performant engine that enables DevOps and security teams to quickly clean up over-permissioned IAM accounts on GCP infrastructure. By leveraging GCP IAM Recommender APIs and the Cloudmarker framework, CureIAM automatically enforces least privilege principle on a daily basis, and helps to ensure that only the necessary permissions are granted to GCP accounts.

Key Features

- Config driven workflow for easy customization
- Scalable and production-grade design
- Embedded scheduling for daily enforcement
- Plugin-driven architecture for additional functionality
- Track actionable insights and records actions for audit purposes
- Scoring and enforcement of recommendations to ensure safety and security

https://github.com/gojek/CureIAM
</details>

<details>
  <summary>PyExfil - A Python Data Exfiltration & C2 Framework</summary>

PyExfil is a python data exfiltration package. It is currently an open source package allowing everyone to download, use and edit the code. It has several modules classified in 4 types of data exfiltration purposes. It is designed to enable Security personnel to test their Data Leakage Prevention mechanisms by attempting to leak various types of data and examine alerting and prevention mechanisms employed in their infrastructure.

Github: https://github.com/ytisf/PyExfil  
</details>

<details>
  <summary>SCodeScanner (SourceCodeScanner)</summary>
  
  SCodeScanner stands for Source Code scanner where the user can scans the source code for finding the Critical Vulnerabilities. The main objective for this scanner is to find the vulnerabilities inside the source code before code gets published in Prod.
  
  Github: https://github.com/agrawalsmart7/scodescanner
  
</details>

<details>
  <summary>AzureGoat : A Damn Vulnerable Azure Infrastructure</summary>
  
AzureGoat is a vulnerable by design infrastructure on Azure featuring the latest released OWASP Top 10 web application security risks (2021) and other misconfiguration based on services such as App Functions, CosmosDB, Storage Accounts, Automation and Identities. AzureGoat mimics real-world infrastructure but with added vulnerabilities. It features multiple escalation paths and is focused on a black-box approach.

https://github.com/ine-labs/AzureGoat 
</details>

<details>
  <summary>BlueMap - An Interactive Tool for Azure Exploitation</summary>
  
As demonstrated in BlackHat UK - BlueMap helps cloud red teamers and security researchers identify IAM misconfigurations, information gathering, and abuse of managed identities in interactive mode without ANY third-party dependencies. No more painful installations on the customer's environment, and No more need to custom the script to avoid SIEM detection!

The tool leaves minimum traffic in the network logs to help during red team engagements from on-prem to the cloud. Developed in Python and implemented all Azure integrations from scratch with zero dependencies on Powershell stuff. The idea behind the tool is to let security researchers and red team members have the ability to focus on more Opsec rather than DevOps stuff.

 https://github.com/SikretaLabs/BlueMap
</details>


<details>
  <summary>ICS Forensics Tool</summary>
  
  ICS Forensics Tools is an open source forensic toolkit for analyzing Industrial PLC metadata and project files. Microsoft ICS Forensics Tools enables investigators to identify suspicious artifacts on ICS environment for detection of compromised devices during incident response or manual check. ICS Forensics Tools is open source, which allows investigators to verify the actions of the tool or customize it to specific needs, currently support Siemens S7.
  
  Github: https://github.com/microsoft/ics-forensics-tools
  
</details>

<details>
  <summary>Damn Vulnerable Bank</summary>
  
With over 2.5 billion devices and millions of apps, Android is ruling the market. Developers had additional responsibility to protect the information and integrity of their users. Considering these high numbers, preventive measures should be taken to secure Android applications used by people across the globe.

We built an open-source vulnerable Banking application, a clone close to real-world banking applications. The existing vulnerable applications cover only basic OWASP vulnerabilities. Our vulnerable application covers multiple things like Binary analysis, Debugger detection bypasses, Frida analysis, writing custom code to decrypt data, and a lot more along with basic OWASP vulnerabilities. This product will be a one-stop place for android application security enthusiasts.

Github: https://github.com/rewanthtammana/Damn-Vulnerable-Bank
  
</details>

<details>
  <summary>Gerobug: Open-Source Private (Self-Managed) Bug Bounty Platform</summary>
  
  Are you a company, planning to have your own bug bounty program, with minimum budget? We got you!

We are aware that some organizations have had difficulty establishing their own bug bounty program.
If you know what you're doing, using a third-party managed platform usually comes with a hefty price tag and increased security concerns.
However, creating your own independently run platform will take time and effort.

GEROBUG FEATURES:
Homepage
This should be the only page accessible by public, which contains Rules and Guidelines for your bug bounty program.

Email Parser
Bug Hunter will submit their findings by email, which Gerobug will parse, filter, and show them on dashboard.

Auto Reply and Notification
Bug Hunter's inquiries will be automatically replied and notified if there any updates on their report.
Company will also be notified via Slack if there any new report.

Report Management
Manage reports easily using a kanban model.

Report Filtering and Flagging
Reports from Bug Hunter will be filtered and flagged if there are duplicate indication.

Email Blacklisting
Gerobug can temporarily block and release emails that conducted spam activity

Auto Generate Certificate
We can generate certificate of appreciations for bug hunters so you don't have to ;)

Hall of Fame / Wall of fame / Leaderboard
Yeah we have it too

Github: https://github.com/gerobug/gerobug
  
</details>

<details>
  <summary>PurpleSharp: Automated Adversary Simulation</summary>
  
Defending enterprise networks against attackers continues to present a difficult challenge for blue teams. Prevention has fallen short; improving detection & response capabilities has proven to be a step in the right direction. However, without the telemetry produced by adversary behavior, building and testing detection capabilities will be a challenging task.

PurpleSharp is an open-source adversary simulation tool written in C# that executes adversary techniques against Windows environments. The resulting telemetry can be leveraged to measure and improve the efficacy of a detection program. PurpleSharp executes different behavior across the attack lifecycle following the MITRE ATT&CK Framework’s tactics: execution, persistence, privilege escalation, credential access, lateral movement, etc.

Github: https://github.com/mvelazc0/PurpleSharp
  
</details>

<details>
  <summary>canTot: A CAN Bus Hacking Framework for Car Hacking</summary>
  

canTot is a CAN Bus hacking framework that focuses on known CAN Bus vulnerabilities or fun CAN Bus hacks. It is a Python-based CLI framework based on sploitkit and is easy to use because it is similar to working with Metasploit. It can also be used as a guide for pentesting vehicles and learning python for Car Hacking the easier way. This is not to reinvent the wheel of known CAN fuzzers, car exploration tools like caring caribou, or other great CAN analyzers out there. But to combine all the known vulnerabilities and fun CAN bus hacks in automotive security.

Github: https://github.com/shipcod3/canTot  
</details>

<details>
  <summary>uftrace: Dynamic Function Tracing Tool for C/C++/Rust programs</summary>
  
uftrace is a function tracing tool that helps in the analysis of C/C++/Rust programs. It hooks into the entry and exit of each function, recording timestamps as well as the function's arguments and return values. uftrace is capable of tracing both user and kernel functions, as well as library functions and system events providing an integrated execution flow in a single timeline.

Initially, uftrace only supported function tracing with compiler support. However, it now allows users to trace function calls without recompilation by analyzing instructions in each function prologue and dynamically and selectively patching those instructions.

Users can also write and run scripts for each function entry and exit using python/luajit APIs to create custom tools for their specific purposes.

uftrace offers various filters to reduce the amount of trace data and provides visualization using Chrome trace viewer and flame graphs, allowing for a big picture view of the execution flow.

uftrace was open sourced in 2016 and has been developed at https://github.com/namhyung/uftrace.
  
</details>

<details>
  <summary>Vajra - Your Weapon To Cloud</summary>
  
Vajra is a UI-based tool with multiple techniques for attacking and enumerating in the target's Azure and AWS environments. It features an intuitive web-based user interface built with the Python Flask module for a better user experience. The primary focus of this tool is to have different attacking techniques all in one place with a web UI interface
The term Vajra refers to the Weapon of God Indra in Indian mythology (God of Thunder & Storms). It's a connection to the cloud makes it a perfect name for the tool.
Vajra presently supports Azure and AWS Cloud environments, with plans to add support for Google Cloud Platform and certain OSINT in the future.

Github: https://github.com/TROUBLE-1/Vajra
  
</details>

<details>
  <summary>KICS - Your IaC Secure Now!</summary>
  
KICS stands for Keeping Infrastructure as Code Secure. It is open source and is a must-have for any cloud native project to find security vulnerabilities, compliance issues, and infrastructure misconfigurations early in the development cycle of the underlying infrastructure-as-code (IaC).

KICS supports about 20 different technologies including Terraform, Cloudformation, Kubernetes, Docker, over several cloud providers like AWS, Microsoft Azure or Google Cloud. It is the only open-source project that has achieved any Center for Internet Security (CIS) certification.

KICS is fully customizable and extensible by the addition of rules for new vulnerabilities. It is available as a Docker image, and is paired in multiple platforms to leverage its integration on the development life-cycle and the DevSecOps mentality of its users. Gitlab has chosen KICS as its default IaC scanner; it is also available in ArgoHub, as a hook in TerraformCloud or as a Github Action for Github workflows.

One of the most recent features of KICS is auto remediation. With this feature KICS goes full cycle in preventing vulnerable code from going into production by scanning the code, exposing the issues, and automatically remediating them. Such a feature is both available from the CLI interface, or via a plugin for the Visual Studio Code editor, where we bring together auto-remediation and real-time scanning. As the developer writes IaC scripts, KICS automatically looks for vulnerabilities, proposes fixes and remediates them. By the time the IaC scripts are finished, developers are rest assured that it is safe to go into production. This is shift-left security brought to its splendor.

Github https://github.com/Checkmarx/kics
  
</details>

<details>
  <summary>T3SF (Technical TableTop Exercises Simulation Framework)</summary>
  
T3SF is a framework that offers a modular structure for the orchestration of events from a master scenario events list (MSEL) together with a set of rules defined for each exercise and a configuration that allows defining the parameters of the correspondent platform. The main module performs the communication with the specific module (Discord, Slack, Telegram, WhatsApp, Teams, etc.) which allows the events to be presented in the input channels as injects for each platform. Also, the framework supports different use cases: single organization-multiple areas, multiple organization-single area, and multiple organization-multiple areas. It has been successfully tested in exercises with international companies, which allowed us to validate its commercial level.

Tabletop exercises have 2 approaches: traditional (scenarios with discussion) and modern (automatic events on a platform). The 1st platform was funded by the DHS (USA) with USD20 MM over 10 years. In 2021 we proposed a novel approach using free platforms, which allowed the development of a free and open source framework.

The original research paper presented and published at the IEEE ARGENCON 2022 academic congress, under the title "Cybersecurity Incident Response Simulation for Organizational and Classroom Learning." Preprint available at IEEE TechRxiv: https://www.techrxiv.org/articles/preprint/Cybersecurity_incident_response_tabletop_simulations_for_learning_in_classrooms_and_organizations/20317416/1/files/36346944.pdf

The tool itself was first presented an released in the most important cybersecurity conference in Spain in (RootedCon 2022) and then updated and presented in the most important cybersecurity conference in Latin America (Ekoparty 2022). Video available at YouTube: https://www.youtube.com/watch?v=3jVkKvVn1TY

This version is a major update, that includes a code rewrite, GUI frontend, new features, and an automatic inject creation engine (sentences in Spanish and English).

Github: https://github.com/Base4Security/T3SF
  
</details>

<details>
  <summary>unblob</summary>

One of the major challenges of embedded security analysis is the accurate extraction of arbitrary firmwares.

While binwalk has been the de-facto standard for firmware extraction since its early days, it proved to be limited in an environment where we needed to analyze heterogeneous firmwares from potentially malicious uploaders at scale.

In this talk we will introduce the audience to our specific use case, the limits of existing extraction tools, and how we overcame them by developing our very own firmware extraction framework, named unblob.

unblob is an accurate, fast, and easy-to-use extraction suite. unblob parses unknown binary blobs for more than 30 different archive, compression, and file-system formats, extracts their content recursively, and carves out unknown chunks that have not been accounted for. This turns unblob into the perfect companion for extracting, analyzing, and reverse engineering firmware images.

Similar to what HD Moore did 19 years ago when he started gathering exploit scripts in a single unifying framework with Metasploit, we'd like to provide reverse engineers with an easy to use and extensible framework to extract custom formats. Our hope is to provide a home to firmware reversers and help them not rewriting the same code every time they need to support a new vendor format.
  
Github:  https://github.com/onekey-sec/unblob
</details>

<details>
  <summary>eBPFShield: Advanced IP-Intelligence & DNS Monitoring using eBPF</summary>
   
eBPFShield is a powerful security tool that utilizes eBPF and Python to provide real-time IP-Intelligence and DNS monitoring. By executing in kernel space, eBPFShield avoids costly context switches, making it a high-performance solution for detecting and preventing malicious behavior on your network. The tool offers efficient monitoring of outbound connections and comparison with threat intelligence feeds, making it an effective solution for identifying and mitigating potential threats. The tool includes features such as DNS monitoring, IP-Intelligence, and the ability to pull down public threat feeds.

Additionally, it includes a roadmap for future developments such as support for IPv6, automated IP reputation analysis using Machine Learning algorithms, and integration with popular SIEM systems for centralized monitoring and alerting.

eBPFShield is especially useful for companies and organizations that handle sensitive information and need to ensure the security of their networks. It's an efficient solution to monitor and protect servers from potential threats and it can help to prevent data breaches and other cyber attacks.

Github: https://github.com/sagarbhure/eBPFShield
</details>

<details>
  <summary>Elkeid -- Open-sourced Cloud Workload Protection Platform</summary>
 
Ekeid is an open-source solution that is derived from ByteDance's internal best practices, which can meet the security requirements of various workloads such as hosts, containers, container clusters, and Serverless. With the unified design and integration of HIDS, Container Security, RASP, and K8S auditions all into one platform to meet the complex security requirements of different workload capacities in the current industry. At the same time, it can also implement multi-component capability association. The most valuable part is that each component of Elkeid has passed ByteDance's massive data and years of practical testing.

Github: https://github.com/bytedance/Elkeid
</details>

<details>
  <summary>tty2web - Share your terminal as a web application (bind/reverse)</summary>
  
tty2web can take any console program and convert it into a web application. It provides a proper console for your shell needs directly inside your browser, which means programs like vim, mc, or any program that needs tty will work as expected by default. Features include support for both bind and reverse mode, which is useful for penetration testing and NAT traversal, bidirectional file transfer, reverse SOCKS 5 functionality by emulating the regeorg interface, and API support for executing commands (imagine having a RESTful interface to your operating system shell). It supports collaboration and sharing between teams, is multiplatform, and runs well on Unix/Linux-based OSs running container payloads. It is based on gotty but has been heavily improved for security and penetration tester needs.

Github: https://github.com/kost/tty2web  
</details>

<details>
  <summary>AWSGoat : A Damn Vulnerable AWS Infrastructure</summary>
  
AWSGoat is a vulnerable by design infrastructure on AWS featuring the latest released OWASP Top 10 web application security risks (2021) and other misconfiguration based on services such as IAM, S3, API Gateway, Lambda, EC2, and ECS. AWSGoat mimics real-world infrastructure but with added vulnerabilities. It features multiple escalation paths and is focused on a black-box approach.

Github: https://github.com/ine-labs/AWSGoat  
</details>

<details>
  <summary>Build Your Own Reconnaissance System with Osmedeus Workflow Engine</summary>

Osmedeus is a is a workflow framework designed to perform reconnaissance, with a focus on identifying the attack surface and conducting security testing on the specified target, including vulnerability scanning, port scanning, and content discovery

Github: https://github.com/j3ssie/osmedeus
</details>

<details>
  <summary>GCPGoat : A Damn Vulnerable GCP Infrastructure</summary>
  
  GCPGoat is a vulnerable by design infrastructure on GCP featuring the latest released OWASP Top 10 web application security risks (2021) and other misconfiguration based on services such as IAM, Storage Bucket, Cloud Functions and Compute Engine. GCPGoat mimics real-world infrastructure but with added vulnerabilities. It features multiple escalation paths and is focused on a black-box approach.
  
  Github: https://github.com/ine-labs/GCPGoat
  
</details>





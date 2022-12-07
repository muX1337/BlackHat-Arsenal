# BlackHat Arsenal EU 2022 

Links to the repositories or other stuff of the BlackHat EU 2022. 

<details>
  <summary>RFQuack: A Versatile, Modular, RF Security Toolkit</summary>
  Software-defined radios (SDRs) are indispensable for signal reconnaissance and physical-layer dissection, but despite we have advanced tools like Universal Radio Hacker, SDR-based approaches require substantial effort. Contrarily, RF dongles such as the popular Yard Stick One are easy to use and guarantee a deterministic physical-layer implementation. However, they're not very flexible, as each dongle is a static hardware system with a monolithic firmware. We present RFquack, an open-source tool and library firmware that combines the flexibility of a software-based approach with the determinism and performance of embedded RF frontends. RFquack is based on a multi-radio hardware system with swappable RF frontends, and a firmware that exposes a uniform, hardware-agnostic API. RFquack focuses on a structured firmware architecture that allows high- and low-level interaction with the RF frontends. It facilitates the development of host-side scripts and firmware plug-ins, to implement efficient data-processing pipelines or interactive protocols, thanks to the multi-radio support. RFquack has an IPython shell and 9 firmware modules for: spectrum scanning, automatic carrier detection and bitrate estimation, headless operation with remote management, in-flight packet filtering and manipulation, MouseJack, and RollJam (as examples). We used RFquack in high-schools to teach digital RF protocols, to setup RF hacking contests, and to analyze industrial-grade devices and key fobs, on which we found and reported 11 vulnerabilities in their RF protocols.
  
  https://github.com/rfquack/RFQuack
</details>

<details>
  <summary>Prowler v3 the handy multi-cloud security tool</summary>
  Prowler is an Open Source security tool to perform AWS, Azure, GCP and OCI security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness. It contains hundreds of controls covering CIS, PCI-DSS, ISO27001, GDPR, HIPAA, FFIEC, SOC2, AWS FTR, ENS and custom security frameworks.
  
  https://github.com/prowler-cloud/prowler
</details>

<details>
  <summary>OMLASP - Open Machine Learning Application Security Project</summary>
  Generally, when deploying applications that use Machine Learning or Deep Learning algorithms, only security audits check for common vulnerabilities. However, these algorithms are also exposed to other vulnerabilities or weaknesses that attackers could exploit. A framework, called OMLASP - Open Machine Learning Application Security Project, is being developed to gather a list of attack and mitigation techniques for these algorithms. This Framework aims to become a standard for auditing Machine Learning algorithms and has been divided into the following two sections:

• Security: the attack surface and attack scenarios will be defined and the capabilities and goals of the attackers. The different attack and defense techniques will be described in-depth to define a methodology to perform an audit of these algorithms.

• Biases: the reasons, types, and solutions will be explained in detail to define a methodology to minimize them. This part is still under development.
  
  https://github.com/Telefonica/OMLASP
  
</details>


<details>
  <summary>Mimicry: An Active Deception Tool</summary>
In incident response scenarios, intercepting attacks or quarantining backdoors is a common response technique. The adversarial active defense will immediately make the attacker perceive that the intrusion behavior is exposed, and the attacker may try to use defense evasion to avoid subsequent detection. These defense evasion may even result in later attacks going undetected. If we mislead or deceive the attacker into the honeypot, we can better consume the attacker's time cost and gain more response time.

We invented a series of toolkits to deceive attackers during the "kill-chain" . For Example:

Exploitation:
1. We return success and mislead the attacker into the honeypot for brute-force attacks.
2. We will simulate the execution of web attack payloads to achieve the purpose of disguising the existence of vulnerabilities in the system.

Command & Control:
1. For the Webshell scenario, we will replace the Webshell with a proxy and transfer the Webshell to the honeypot. When the attacker accesses Webshell, the proxy will forward his request to the honeypot.
2. For the reverse shell, we will inject the shell process and forward the attacker's operation to the shell process in the honeypot.
3. For the backdoor, we will dump the process's memory, resources, etc., and migrate it to the honeypot to continue execution.

https://github.com/chaitin/Mimicry
</details>

<details>
  <summary>MI-X - Am I Exploitable?</summary>
  
  'Am I Exploitable?', is an open source tool aimed at effectively determining whether a local host or a running container image is truly vulnerable to a specific vulnerability by accounting for all factors which affect *actual* exploitability. The tool prints the logical steps it takes in order to reach a decision and can generate a flow chart depicting the complete logical flow.
  
https://github.com/Rezilion/mi-x  
</details>

<details>
  <summary>Ipa-medit: Memory modification tool for iOS apps without Jailbreaking</summary>
  
  Ipa-medit is a memory search and patch tool for resigned ipa without jailbreaking. It supports iOS apps running on iPhone and Apple Silicon Mac. It was created for mobile game security testing. Many mobile games have jailbreak detection, but ipa-medit does not require jailbreaking, so memory modification can be done without bypassing the jailbreak detection.

Memory modification is the easiest way to cheat in games, it is one of the items to be checked in the security test. There are also cheat tools that can be used casually like GameGem and iGameGuardian. However, there were no tools available for un-jailbroken device and CUI, Apple Silicon Mac. So I made it as a security testing tool.

I presented a memory modification tool ipa-medit which I presented at Black Hat USA 2021 Arsenal. At that time, it could only target iOS apps running on iPhone, but now it supports iOS apps running on the Apple Silicon Mac. The Apple Silicon Mac was recently released and allows you to run iOS apps on macOS. For memory modification, I'll explain how the implementation and mechanisms are different for iOS apps running on iPhone or Apple Silicon Mac.

GitHub: https://github.com/aktsk/ipa-medit

</details>


<details>
  <summary>TSURUGI LINUX: DFIR INVESTIGATIONS, MALWARE ANALYSIS AND OSINT ACTIVITIES MADE EASY</summary>
  Any DFIR analyst knows that every day in many companies, it doesn't matter the size, it's not easy to perform forensics investigations often due to a lack of internal information (like mastery of all IT architecture, having the logs or the right one...) and ready to use DFIR tools.

As DFIR professionals we have faced these problems many times and so we decided last year to create something that can help those who will need the right tool at the "wrong time" (during a security incident).

And the answer is the Tsurugi Linux project that, of course, can be used also for educational purposes.
After more than a year since the last release, a Tsurugi Linux special BLACKHAT EDITION with this major release will be shared with the participants before the public release.

https://tsurugi-linux.org/index.php
</details>

<details>
  <summary>Defascan: Defacement Scan and Alert</summary>
  Web server defacement is also a major problem especially for government sites. Therefore, this project intends to develop a web server defacement detection tool named DefaScan. This tool, DefaScan will detect a defaced website and notify about it.
  
https://github.com/RamXtha/DefaScan  
</details>

<details>
  <summary>CQSysmon Toolkit: Advanced System Monitoring Toolkit</summary>
  Our toolkit has proven to be useful in the 25000 computers environment. It relies on a free Sysmon deployment and its goal is to boost information delivered by the original tool. CQSysmon Toolkit allows you to extract information about what processes have been running in the operating system, get their hashes and submit them into Virus Total for the forensic information about the malware cases. It also allows to extract information into spreadsheet about what types of network connections have been made: what is the destination IP address, which process was responsible for it and who is the owner of IP. The toolkit also allows to extract information about the current system configuration and compare it with the other servers and much more that allows to become familiar of what is going on in your operating system. There is a special bonus tool in a toolkit that allows to bypass some parts of the Sysmon with another tool that allows to spot that situation so that everything stays in control. CQSysmon Toolkit allows you to established detailed monitoring of the situation on your servers and it is a great complement to the existing forensic tools in your organization.
  
  
Sysinternals(Sysmon is part of it): https://learn.microsoft.com/en-us/sysinternals/  

Sysmon  https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Sysmon Installation Guide: https://cqureacademy.com/blog/hacks/sysmon

Other-Tools of CQ: https://github.com/BlackDiverX/cqtools

</details>


<details>
  <summary>a bridge to laser beam from IR remote controller</summary>
  
 This summer, Michihiro Imaoka presented IR-BadUSB at the Black Hat USA 2022 Arsenal. 

This IR-BadUSB allows an attacker to control a BadUSB plugged into a target's PC with an infrared remote control. Since this IR-BadUSB uses a household infrared remote control, the attacker and the IR-BadUSB must be within the infrared range of this remote control. Basically, the target and the attacker must be in the same room. Therefore, various improvements have been made to extend the reach of this IR-BadUSB.

This is one such attempt. This is an attempt to extend the limited range of infrared remote control units for home appliances by converting them into laser beams and irradiating them. Let us explain the method. The module that emits the laser beam has a wavelength of 940 nm, the same wavelength as the infrared ray for home appliances.

The transmitted beam from the infrared remote control for home appliances is received by an infrared receiver such as VS1838B. After adding a 38 KHz subcarrier to the received signal, the laser module is driven by a transistor or similar device.

Perhaps if IR-BadUSB is located near a window, it would be possible to control IR-BadUSB from outdoors. Even if the IR-BadUSB is not near a window, it may be possible to control other IR-BadUSBs if the IR laser beam is reflected and diffused by something inside the room. Infrared light is invisible to the human eye, so the target will not notice it. The only way to prevent this might be to close the curtains or lower the blinds.

Operating the IR-BadUSB with an infrared laser beam does not require a PC or other large device, since it is a remote control for home appliances. If you have a remote control for home appliances that you have used to operate IR-BadUSB, you can use that remote control. No separate programming is required.

 https://github.com/imaoca/irBadUSBbyButton
  
</details>

<details>
  <summary>The Eye of Falco: You can escape but not hide</summary>

Container technologies rely on features like namespaces, cgroups, SecComp filters, and capabilities to isolate different services running on the same host. However, SPOILER ALERT: container isolation isn't bulletproof. Similar to other security environments, isolation is followed by red-teamer questions such as, "How can I de-isolate from this?"

Capabilities provide a way to isolate containers, splitting the power of the root user into multiple units. However, having lots of capabilities introduces complexity and a consequent increase of excessively misconfigured permissions and container escape exploits, as we have seen in recently discovered CVEs.

Falco is a CNCF open source container security tool designed to detect anomalous activity in your local machine, containers, and Kubernetes clusters. It taps into Linux kernel system calls and Kubernetes Audit logs to generate an event stream of all system activity. Thanks to its powerful and flexible rules language, Falco will generate security events when it finds malicious behaviors as defined by a customizable set of Falco rules.

The recent Falco update introduced the feature to keep track of all the syscalls that may modify a thread's capabilities, modifying its state accordingly, allowing Falco to monitor capabilities assigned to processes and threads. This new feature allows users to create detection over those malicious misconfigurations and automatically respond by implementing actions to address the issue

In this talk, we explain how you can use Falco to detect and monitor container escaping techniques based on capabilities. We walk through show real-world scenarios based on recent CVEs to show where Falco can help in detection and automatically respond to those behaviors
  
https://falco.org/

https://github.com/falcosecurity/falco
</details>

<details>
  <summary>SquarePhish: Combining QR Codes and OAuth 2.0 Device Code Flow for Advanced Phishing Attacks</summary>
  
SquarePhish is an advanced phishing tool that uses a technique combining the OAuth Device code authentication flow and QR codes. Previous OAuth 2.0 Device Code phishing tools (like PhishInSuits) required a user open the phishing email and authenticate within 15 minutes of the email being sent. This drastically decreased the chances of a successful phish, as many emails expired prior to user interaction.

SquarePhish fixes this issue, by decoupling the initial email from the OAuth Device Code flow. Combining this technique, QR Codes, and a Microsoft MFA pretext we are able to perform advanced phishing attacks.

We have also added a subtool called Rephresh that utilizes undocumented Microsoft functionality that allows the SquarePhish obtained tokens to be swapped out for tokens for other applications.

 https://github.com/secureworks/squarephish 
  
</details>


<details>
  <summary>Reversing MCU with Firmware Emulation</summary>
  
A microcontroller unit (MCU) is a small computer on a single metal-oxide-semiconductor (MOS) integrated circuit (IC) chip. It is widely used in various types of devices, appliances, automobiles, and many more. Recently MCU security has been raised as a major concern among users and operators, as MCU vulnerabilities can be catastrophic. For this reason, it is important to audit MCU code for security issues. Unfortunately, due to the limited resources on MCU, the on-device test for MCU is not feasible. Besides, there are no emulation solutions able to provide a full instrumentation analysis platform for MCU firmware.

On the other hand, the tight coupling between MCU and hardware peripherals makes it difficult to build an MCU firmware emulator. This greatly hinders the application of dynamic analysis tools in firmware analysis, such as fuzzing.

This talk discusses how we emulated MCU emulation without real peripheral hardware. This requires to model peripheral's registers and interrupts, and implements their internal logic based on the official peripheral documentation and hardware abstraction layer (HAL). We can now emulate widely used MCU chips from top MCU vendors such as STM, Atmel, NXP, and so on. Each of them includes a diverse set of peripherals, including UART, I2C, SPI, ADC, Ethernet, SD Card, Timer, etc.

Upon our emulation, we built several analysis tools for various firmware formats, such as ELF, Binary, and Intel Hex, which are widely used in MCU libraries (RTOS, Arduino, Protocol Stack, etc). We are able to perform advanced tasks, such as:

- Instrument and hijack MCU's activities (e.g, reads and writes to peripherals).
- Save and restore current peripheral/execution states (e.g. register and interrupts).
- Supports multi-threaded firmware, such as RTOS.
- Hijack the interrupts from peripherals, so users can control the scheduling policy of multi-threaded firmware.

To demonstrate the power of our work, we will have live demos to show some exciting cases:

- Emulate MCU with external devices via SPI. UART and I2C
- Fuzz MCU firmware to find 0days with a customized AFL fuzzer.
- Password brute forcing for MCU firmware
- To solve some MCU challenges on CTFs

New code and demo will be released after the talk.  
  
</details>

<details>
  <summary>JavaScript Obfuscation - It's All About the P-a-c-k-e-r-s</summary>
  
  The usage of JavaScript obfuscation techniques have become prevalent in today's threats, from phishing pages, to Magecart, and supply chain injection to JavaScript malware droppers all use JavaScript obfuscation techniques on some level.

The usage of JavaScript obfuscation enables evasion from detection engines and poses a challenge to security professionals, as it hinders them from getting quick answers on the functionality of the examined source code.

Deobfuscation can be technically challenging (sometimes), risky (if you don't know what you are doing), and time consuming (if you are lazy, as I am). Yet, the need to find and analyze high scaled massive attacks using JavaScript obfuscation is a task I'm faced with on a daily basis.

In this arsenal showcase I will present a lazy, performance cost effective approach, focusing on the detection of JavaScript packer templates. Once combined with threat intelligence heuristics, this approach can predict the maliciousness level of JavaScript with high probability of accuracy.

In addition, the showcase will include insights based on detections of the tool that were collected from the threat landscape, including some of the challenges associated with benign websites using obfuscation.

The showcase will also suggest techniques showing how the tool obfuscation detection can also be combined with other threat intelligence signals and heuristics, that can lead to better classification of detect obfuscated code as being malicious.

Youtube-Presentation: https://www.youtube.com/watch?v=uSOzC-o0kr8
</details>

<details>
  <summary>Unravelling the Mysteries of Shellcode with SHAREM: A Novel Emulator and Disassembler for Shellcode</summary>
  Shellcode can be highly cryptic; comprehending its functionality is not straightforward; shellcode may be bewildering, especially if encoded. SHAREM is a cutting-edge Shellcode Analysis Framework, with both emulation and its own disassembler. In this talk, we explore SHAREM's powerful, unique capabilities, to unravel the mysteries of shellcode.

Windows syscalls have become trendy in offensive security, and SHAREM is the only tool that can emulate and log all user-mode Windows syscalls. Additionally, SHAREM also emulates and logs more than 16,000 WinAPI functions. SHAREM is the only shellcode tool to parse and discover not only parameters, but also structures passed as parameters, displaying all structure fields to users. SHAREM doesn't present parameters as hexadecimal values, but converts each to human readable format, in vivid colors.

Disassemblers like IDA Pro and Ghidra often are poor at disassembling shellcode accurately. SHAREM's disassembler is significantly more accurate with its original analysis capabilities. SHAREM additionally can uniquely integrate emulation results to provide flawless disassembly. Novel signature identifications are used to identify each function in the shellcode, along with parameter values. SHAREM uses unique capabilities to accurately identify data, presenting data the correct way, not as misinterpreted Assembly instructions.

SHAREM provides unprecedented capabilities with encoded shellcode. Not only does it fully deobfuscate shellcode through emulation, discovering both WinAPIs and syscalls, but it automatically recovers the shellcode's deobfuscated form. SHAREM presents error-free disassembly of its decoded form, with function calls and parameters labelled.

SHAREM provides other features to better understand shellcode. SHAREM's complete-code coverage ensures that no functionality is missed. Timeless debugging lets users unwind a complex shellcode, seeing hundreds of thousands of instructions executed and the CPU state before and after each. SHAREM also outputs to JSON format; while ideal for individual users, SHAREM can be deployed as part of automated web services. SHAREM is a game-changer.

https://github.com/bw3ll/sharem
</details>


<details>
  <summary>EMBA – From firmware to exploit</summary>
IoT (Internet of Things) and OT (Operational Technology) are the current buzzwords for networked devices on which our modern society is based on. In this area, the used operating systems are summarized with the term firmware. The devices themselves, also called embedded devices, are essential in the private and industrial environments as well as in the so-called critical infrastructure.

Penetration testing of these systems is quite complex as we have to deal with different architectures, optimized operating systems, and special protocols. EMBA is an open-source firmware analyzer with the goal to simplify and optimize the complex task of firmware security analysis. EMBA supports the penetration tester with the automated detection of 1-day vulnerabilities on a binary level. This goes far beyond the plain CVE detection: With EMBA you always know which public exploits are available for the target firmware. Besides the detection of already known vulnerabilities, EMBA also supports the tester on the next 0-day. For this, EMBA identifies critical binary functions, protection mechanisms, and services with network behavior on a binary level. There are many other features built into EMBA, such as fully automated firmware extraction, finding file system vulnerabilities, hard-coded credentials, and more.

EMBA is the open-source firmware scanner, created by penetration testers for penetration testers.  

https://github.com/e-m-b-a/emba
</details>

<details>
  <summary>Packing-Box: Playing with Executable Packing</summary>
  
 This Docker image is an experimental toolkit gathering detectors, packers, tools and machine learning mechanics for making datasets of packed executables and training machine learning models for the static detection of packing. It aims to support PE, ELF and Mach-O executables and to study the best static features that can be used in learning-based static detectors.
 
 https://github.com/packing-box/docker-packing-box
</details>

<details>
  <summary>vAPI: Vulnerable Adversely Programmed Interface</summary>
 vAPI is a Vulnerable Interface in a Lab like environment that mimics the scenarios from OWASP API Top 10 and helps the user understand and exploit the vulnerabilities according to OWASP API Top 10 2019. Apart from that, the lab consists of some more exercises/challenges related to advanced topics related to Authorization and Access Control.
 
 https://github.com/roottusk/vapi
</details>


<details>
  <summary>Extensible Azure Security Tool</summary>
  
Extensible Azure Security Tool (Later referred to as E.A.S.T) is a tool for assessing Azure and to some extent Azure AD security controls. The primary use case of EAST is Security data collection for evaluation in Azure Assessments. This information (JSON content) can then be used in various reporting tools, which we use to further correlate and investigate the data.
  
  
  https://github.com/jsa2/EAST
</details>

<details>
  <summary>DotDumper: automatically unpacking DotNet based malware</summary>
 Analysts at corporations of any size face an ever-increasing amount of DotNet based malware. The malware comes in all shapes and forms, ranging from skittish stealers all the way to nation-state-backed targeted malware. The underground market, along with public open-source tools, provides a plethora of ways to obfuscate and pack the malware. Unpacking malware is time-consuming, difficult, and tedious, which poses a problem.

https://github.com/advanced-threat-research/DotDumper 
</details>

<details>
  <summary>CQForensic: The Efficient Forensic Toolkit</summary>
 CQForensic Toolkit enables you to perform detailed computer forensic examinations. It guides you through the information gathering process providing data for analysis and extracting the evidence. CQForensic can build an attack timeline, extract information from the USN journal, recover files, also from MFT, decrypt user's and system's stored secrets, like encrypted data, extract information from Prefetch and from Remote Desktop Session cache, extract information from the configuration of the used for administration tools. It also contains toolkit for memory analysis, it extracts information from memory dumps, including the PowerShell commands, complete files, including making them consistent if they were corrupted, like sensitive EVTX files. Our biggest CQKawaii implements custom-made machine learning algorithms to extract from the large logs the anomalies. CQForensic is a very practical toolkit for forensic investigators.
 
</details>

<details>
  <summary>BlueMap</summary>
 BlueMap helps cloud red teamers and security researchers identify IAM misconfigurations, information gathering, and abuse of managed identities in interactive mode without ANY third-party dependencies. No more painful installations on the customer's environment, No more need to custom the script to avoid SIEM detection!


The tool leaves minimum traffic in the network logs so it can help during red team engagements from on-prem to the cloud. Developed in Python and implemented all Azure integrations from scratch with zero dependencies on Powershell stuff. The idea behind the tool is to allow security researchers and red team members to focus on Opsec rather than DevOps stuff.


The tool is currently in the Alpha version and with initial capabilities, but it will evolve with time.

 https://github.com/SikretaLabs/BlueMap
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
  <summary>Invoke-DNSteal: Exfiltrating DNS information "Like a Boss"</summary>
One of the most common problems during Red Team and Ethical Hacking exercises is the possibility of sending information outside the perimeter of an organization without being detected.

 

 Currently, there are a multitude of tools and techniques to perform this task (via HTTP/S, TCP, etc.) as well as the use of covert channels. These covert channels, allow us to send and receive information through protocols designed for other purposes, with the aim of disguising our traffic so as not to be discovered.

 

 In this talk, we will discuss the advantages and disadvantages of using the DNS protocol in an audit, the automation of this process from scratch, and even a new way of use never seen before or used by any other tool of this type.

 https://github.com/JoelGMSec/Invoke-DNSteal
</details>

<details>
  <summary>EmoLoad: Loading Emotet Modules without Emotet</summary>
  
Emotet is one of the most prominent multi-component threats in recent years. Besides the core component, which is often attached to a spam email or downloaded from a malicious URL, Emotet is known to retrieve from its C2 infrastructure additional modules; these modules can be either designed to propel its own operations by, for example, stealing email credentials to be used in future spam waves, or, when the attack is more targeted, engineered to be more a destructive artifact, like ransomware provided by an affiliated group. 


These additional components are meant to be executed by the core module directly from memory, and they are never dropped on disk. Even when payload extraction using dynamic analysis techniques succeeds, loading the extracted modules in isolation inexorably fails as the existence of a custom entry point requires specially crafted data structures to be allocated in memory. These data structures are normally allocated by the core module for various purposes, with only a portion being required by the loaded module. 


EmoLoad is a small but practical tool to successfully execute Emotet modules in isolation. It allocates the required data structures and invokes the custom entry point while allowing customization of the execution environment. It easily allows dynamic analysis without depending on the core module potentially infecting the system, thereby enabling security research tasks such as debugging, IoC extraction, or analysis of the resulting network activity (critical when analyzing Emotet modules that are able to propagate laterally). To further simplify analysis at scale, EmoLoad offers an option to embed the module and the loader together into a standalone executable, making it the perfect candidate for automated submissions to standard sandboxes. 

VM-Ware Blog:  https://blogs.vmware.com/security/2022/12/emoload-loading-emotet-modules-without-emotet.html

https://github.com/vmware-research/emotet-loader
  
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

<details>
  <summary>Patronus: Swiss Army Knife SAST Toolkit</summary>

Patronus is a fully dockerised and comprehensive config driven Security Framework which helps to detect security vulnerabilities in the Software Development Life Cycle of any application. The framework inculcates a highly automated approach for vulnerability identification and management. With Patronus's fully whitebox approach, the framework currently covers four major verticals; Secrets Scanning, Software Composition Analysis, Static Application Security Testing and Asset Inventory. Finding all these four verticals together is a very strenuous task in the industry as no other framework currently solves this like Patronus which provides a fully comprehensive dashboard containing all the four verticals in a single central platform, and this is something very unique to Patronus. Patronus automatically identifies the latest code commits and focuses on the major aspects of the application source code to identify and detect key and high severity vulnerabilities within the application and aims for minimal false positives in the reports.

The framework focuses on the needs of the security engineers and the developers alike with a dedicated web dashboard to abstract all the nitty gritty technicalities of the security vulnerabilities detected and also empowers the user with higher level of vulnerability tracking for better patch management. The dashboard is built completely with analytics, functionality and maintaining ease in mind to demonstrate and display various metrics for the scans and vulnerabilities. It also helps to search, analyse and resolve vulnerabilities on-the-go and provides a completely consolidated vulnerability report.

Patronus is very powerful and hugely reduces the time and efforts of the security team in thoroughly reviewing any application from a security lens. The framework comes with an on-demand scanning feature apart from the scheduled daily automated scans, using which developers and security engineers can scan particular branches and repositories at any point of time in the SDLC, directly from the dashboard or integrations like Slack. The framework is completely adaptable and various softwares like Slack and Jira can be easily integrated directly with Patronus for better accessibility and tracking since most organisations today use these extensively.

https://github.com/th3-j0k3r/Patronus

Slides BlackHat Asia 2022: https://noti.st/th3j0k3r/r2xewr/slides
</details>

<details>
  <summary>HazProne: Cloud Security Ed</summary>
  
HazProne is a Cloud Pentesting Framework that emulates close to Real-World Scenarios by deploying Vulnerable-By-Demand AWS resources enabling you to pentest Vulnerabilities within, and hence, gain a better understanding of what could go wrong and why!!
  
https://github.com/stafordtituss/HazProne 
</details>


<details>
  <summary>Detecting Linux Kernel Rootkits with Tracee</summary>
Linux Kernel Rootkits is an advanced and fascinating topic in cyber security. These tools are stealthy and evasive by design and often target the lower levels of the OS, unfortunately, there aren't many solid security tools that can provide extensive visibility to detect these kinds of tools.

Tracee is a Runtime Security and forensics tool for Linux, utilizing eBPF technology to trace systems and applications at runtime, analyze collected events to detect suspicious behavioral patterns and capture forensics artifacts.

Tracee was presented in BH EU 2020 and BH USA 2021. Thus far we have presented Tracee-ebpf and spoken about its passive capabilities to collect OS events based on given filters, and Tracee-rules, which is the runtime security detection engine. But Tracee has another capability to safely interact with the Linux kernel, which grants Tracee even more superpowers.

Tracee was designed to provide observability of events in running containers. It was released in 2019 as an OSS project, allowing practitioners and researchers to benefit from its capabilities. Now, Tracee has greatly evolved, adding more robust and advanced capabilities. Tracee is a runtime security and forensics tool for Linux, built to address common Linux security issues.

For references see:

https://blog.aquasec.com/ebpf-container-tracing-malware-detection

https://blog.aquasec.com/advanced-persistent-threat-techniques-container-attacks

https://github.com/aquasecurity/tracee
  
</details>

<details>
  <summary>AppsecStudy - open-source elearning management system for information security</summary>
AppsecStudy is an open-source platform for seminars, training, and organizing courses for practical information security for developers and IT specialists. This tool has all the built-in basic requirements needed for organizing normal and productive training.

https://appsec.study/ 
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



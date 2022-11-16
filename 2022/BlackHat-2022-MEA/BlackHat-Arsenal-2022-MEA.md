# BlackHat Arsenal 2022 MEA

Links to the repositories or other stuff of the BlackHat MEA 2022

As long a cannot access the VODs just a short list what I found so far via googlesearch.

<details>
  <summary>Betterscan.io</summary>
  
  Code Scanning/SAST/Static Analysis/Linting using many tools/Scanners with One Report (Code, IaC) - Betterscan Community Edition (CE)

https://www.betterscan.io/
  
</details>

<details>
  <summary>Damn Vulnerable Telecom Network</summary>
  
"Telecom network was closed for years but recent advances in open source telecom opens new doors for telecom hacking. SS7 is the core network protocol in 2G and 3G and Diameter is a Core Protocol for 4G . Many people have proved that this network is unsecured, but no proper tool or vulnerable network is available in the information security community. 

This tool will present security loopholes in SS7 and Diameter network and I’ll be covering the SS7 & Diameter Protocol security, also the real telecom security penetration testing in the lab. The lab's demonstration is prepared from real SS7 & Diameter Penetration testing experience. During this track, I will publish my SS7 & Diameter Penetration Testing Lab named The Damn vulnerable Telecom Network. The talk will first present the basics of this vulnerability including information leaks, denial of service, toll and billing fraud, privacy leaks, and SMS fraud. 

Attendees will be able to understand the basics of the SS7 & Diameter network and lab usage and in addition, Attendees will also understand the different types of attacks in the SS7 network. Currently, LAB is licensed under the AGPL license."

Maybe he will upload a video or more inforamtion on this site: 
https://hackingarchivesofindia.com/hacker/akib_sayyed/
</details>

<details>
  <summary>PMR - PT & VA Management & Reporting
PMR - PT & VA Management & Reporting</summary>
  
PMR (PTVA Management & Reporting) is an open-source collaboration platform that closes the gap between InfoSec Technical teams and Management in all assessment phases, from planning to reporting. Technical folks can focus on assessment methodology planning, test execution ,and engagement collaboration. Whereas management can plan engagements, track progress, assign testers, monitor remediation status, and escalate SLA breaches, this is an All-in-One fancy dashboard.

https://github.com/alenazi90/PMR
</details>

<details>
  <summary>Yet to be Named Mobile Pentesting Tool</summary>
  
Whether you are the on-site security team or a security consultant, chances are when it's time for the regularly schedule penetration test, mobility and BYOD are firmly out of scope. Alas mobility is ripe with exploitable vulnerabilities and avenues of attack as just about any other segment of your typical modern enterprise. Worse still successfully exploited mobile devices can be used as a pivot point into the internal network and your sensitive corporate data. Using our free new toolset we get to the heart of the vulnerability landscape surrounding mobility and give you the ability to bring mobility and the surrounding enterprise mobility security technologies firmly in scope for your security testing. We provide point and click capabilities for common vulnerabilities in mobility, from mobile phishing to malicious applications to good ole memory corruption vulnerabilities that lead to silent jailbreaking or rooting. We will demonstrate a penetration testing scenario for mobility. We will look at the current landscape of available enterprise mobile security products from practically useless original user level mobile anti-virus apps, to the toothier Mobile Threat Defense solutions, as well as Enterprise Mobility Management suites and Mobile Application Management. We will also test the security claims they make, how they can be beneficial to the security of your mobility and enterprise as a whole, and how those products too can be put through their paces via penetration testing.

Does the product that claims to detect zero day exploits fail or succeed to detect even the most noisy of indicators of compromise? Does the product that claims to be able to detect malicious applications fail or succeed to notice when an app is exfiltrating tons of corporate data and dropping all sorts of known exploit files on the file system? You want to know!

 Community Edition Free check pricing:
 https://www.shevirah.com/dagah/
 
 Download Software/Manual
 https://www.shevirah.com/downloads/
  
</details>

<details>
  <summary>WormHex</summary>
  
  Social media applications are increasingly being used in our everyday communications. These applications utilise end-to-end encryption mechanisms which make them suitable tools for criminals to exchange messages. These messages are preserved in the volatile memory until the device is restarted. Therefore, volatile forensics has become an important branch of digital forensics. In this study, the WormHex tool was developed to inspect the memory dump files for Windows and Mac based workstations. The tool supports digital investigators by enabling them to extract valuable data written in Arabic and English through web-based WhatsApp and Twitter applications. The results confirm that social media applications write their data into the memory, regardless of the operating system running the application, with there being no major differences between Windows and Mac.
  
  Paper: https://publications.waset.org/10012579/wormhex-a-volatile-memory-analysis-tool-for-retrieval-of-social-media-evidence
  
</details>

<details>
  <summary>Mr. SIP: SIP-Based Audit and Attack Tool</summary>
  
  Mr.SIP is a functional SIP-based penetration testing tool. It is the most comprehensive offensive VoIP security tool ever developed. Mr.SIP is developed to assist security experts and system administrators who want to perform security tests for VoIP systems and to measure and evaluate security risks. It quickly discovers all VoIP components and services in a network topology along with vendor, brand, and version information, and detects current vulnerabilities, and configuration errors. It provides an environment to assist in performing advanced attacks to simulate abuse of detected vulnerabilities. It detects SIP components and existing users on the network, intervenes, filters, and manipulates call information, develops various DoS attacks, including status-controlled, breaks user passwords, and can test the server system by sending irregular messages.

In the current state, Mr.SIP comprises 9 sub-modules named SIP-NES (network scanner), SIP-ENUM (enumerator), SIP-DAS (DoS attack simulator), SIP-ASP (attack scenario player), SIP-EVA (eavesdropper), SIP-SIM (signaling manipulator), SIP-CRACK (cracker), SIP-SNIFF (sniffer), and SIP-FUZZ (fuzzer).

https://github.com/meliht/Mr.SIP
  
</details>

<details>
  <summary>Backstab: Kill, Dump and Inject into Protected Processes</summary>
  
Protected processes (PPLs) are interesting from an offensive perspective, mainly for three reasons. The first reason is LSA protection, which causes LSASS to be spawned as a PPL and prevents non-PPL processes from obtaining a handle with VM_READ access to LSASS and protects against credential dumping. Second, anti-malware processes are PPL processes, so tampering with PPL introduces the possibility of tampering with EDR processes. Finally, the memory of some PPL processes cannot be scanned by EDRs and that provides some room for evasion.

Common methods to tamper with PPLs are vulnerabilities, handle duplication, and bringing your own signed driver (BYOD). Vulnerabilities get patched, as we have seen with the recent patch that fixed the vulnerability that PPLDump cleverly exploited. Handle duplication is environment-dependent, and one might not find a process with an open handle to the PPL process. BYOD has the challenge of obtaining a valid code signing certificate to sign the driver, and using a vulnerable, yet signed, driver to get kernel-level code execution to disable protection has its own challenges and risks, from causing an unintentional BSOD to the fact that EDR vendors are already flagging vulnerable drivers with available public exploits.

Backstab is a variation of the BYOD technique that leverages the Microsoft-signed Process Explorer driver to obtain a full-access handle to protected processes. Unlike the usual BYOD, there is no custom code execution in memory. We submit the PID to the process explorer driver and obtain a full-access handle to the target PPL. The first version of Backstab served as a demo, focusing on killing anti-malware PPL processes only. The second version, released with this BH talk, contains additional features like dumping protected LSA, injecting into PPL processes, and offers a minimal Backstab version for red teams to be integrated with their custom tools.

https://github.com/Yaxser/Backstab
  
</details>

<details>
  <summary>Hidden in Plain Sight: Developing Use Cases That Nefariously Utilize Twitter's API For The Purpose of Building Covert Communications</summary>
  
 With over 182 billion Tweets being produced by approximately 330 million accounts on Twitter's social media platform just this year in 2019, each account is crafting approximately 552 Tweets. Due to the large volume of traffic and Tweets on this platform, it is a suitable candidate for creating a covert channel that is hidden in plain sight; thus, allowing for covert communications to exist. The paper defines a covert channel as being any type and all forms of communications that are hidden and communicated surreptitiously between different endpoints. By exploiting Twitter's APIs, the channel utilizes two use cases: a malware use case and a command and control server design use case. These two use cases have been implemented to send covert messages, execute commands remotely, and exfiltrate data through an account's user profile page being scraped, parsed, and interpreted. Allowing ambiguity to be established in both use cases in a social media environment where communication between the different hosts would eliminate suspicion and mitigate the risk of detection.

Paper:  https://www.researchgate.net/publication/354323224_Hidden_in_Plain_Sight_Developing_Use_Cases_That_Nefariously_Utilize_Twitter's_API_For_The_Purpose_of_Building_Covert_Communications
  
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
  <summary>Node Security Shield - A Lightweight RASP for NodeJS Application</summary>
  
 Node Security Shield (NSS) is an Open source Runtime Application Self-Protection (RASP) tool which aims at bridging the gap for comprehensive NodeJS security by enabling Developer and Security Engineer to declare what resources an application can access.

 https://github.com/DomdogSec/NodeSecurityShield
  
</details>

<details>
  <summary>MemTracer: Hunting for Forensic Artifacts in Memory</summary>
  MemTracer is a tool that offers live memory analysis capabilities, allowing digital forensic practitioners to discover and investigate stealthy attack traces hidden in memory.

Advanced persistence threat (APT) adversaries use stealthy attack tactics that only leave volatile short-lived memory evidence. The reflective Dynamic-Link Library (DLL) load technique is considered one of the stealthiest attack techniques. Reflective DLL load allows adversaries to load malicious code directly into memory, rather than loading a file from the disk. Thus, reflective DLL load leaves no digital evidence present on the disk. The malicious DLL continues to execute as long as the compromised process is running. Terminating a compromised process leads to the removal of the malicious DLL from memory, and the release of the memory region back to the pool for reallocation. Therefore, memory needs to be examined periodically in order to detect the existence of a malicious DLL that loaded reflectively into memory. 

Loading DLL reflectively produces an unusual memory region’s characteristics that can indicate its existence. The MemTracer tool was developed to efficiently scan memory regions to detect reflective DLL loading symptoms. Mainly, MemTracer aims to detect native .NET framework DLLs that are loaded reflectively. Additionally, MemTracer provides the ability to search for a specific loaded DLL by name, which can retrieve the list of processes that have abnormally loaded the specified module for further investigation.
  
  https://github.com/kristopher-pellizzi/MemTrace
</details>

<details>
  <summary>Vuls Major Update - User Friendly and New Feature Custom Advisories</summary>
  
 Vuls, a GitHub Star 9000+ vulnerability scanner for Linux/FreeBSD servers, is getting a major update.

This update makes it easier for users to use, and implements the ability for users to create their own advisories and custom advisories.

Until now, Vuls vulnerability detection required several vulnerability databases, such as NVD, OVAL, Security Tracker, Metasploit, ExploitDB, etc., to be prepared for each tool.

With this update, only one vulnerability database is needed, and the Vuls binary alone can do everything from preparing the vulnerability database, to scanning the target machine, to detecting vulnerabilities in the scan results.

Having a single vulnerability database contributes to easier management of the vulnerability database and advisories provided.

For example, if one of the multiple vulnerability databases is not updated and has outdated information, the outdated information can cause false positives or misleading information about the status of an exploit.

In addition, even if the development community adds new data sources, if users do not create their own vulnerability databases, they will not receive the advisories that they want to see.

Therefore, it is important to be able to control the advisories that are provided, and if the development community prepares advisories that they want to see, they will be delivered directly to the users.

The custom advisory feature allows users to create their own advisories.

For example CVE-2021-44228 found in Apache Log4j was reported to The Apache Software Foundation on November 25, registered with NVD on December 10, and CPE information was not added until December 13. If users can add their own custom advisories between November 25, when the vulnerability was reported, and December 13, when the CPE information is assigned, they will be alerted to this vulnerability earlier.

Let's automate your Linux/FreeBSD vulnerability detection with evolved Vuls!"

https://github.com/future-architect/vuls
  
</details>

<details>
  <summary>CQPenetrationTesting Toolkit: Powerful Toolset That All Pentesters Want to Have</summary>
  
  CQ Penetration Testing Toolkit supports you in performing complex penetration tests as well as shows the ways to use them, and the situations in which they apply. It guides you through the process of gathering intel about network, workstations, and servers. Common technics for antimalware avoidance and bypass, lateral movement, and credential harvesting. The toolkit allows also for decrypting RSA keys and EFS protected files as well as blobs and objects protected by DPAPI and DPAPI-NG. This powerful toolkit is useful for those who are interested in penetration testing and professionals engaged in pen-testing working in the areas of database, system, network, or application administration. Among published presented tools are CQARPSpoofer, CQCat, CQDPAPIBlobDecrypter, CQMasterKeyDecrypt, CQReverseShellGen, and many more.
  
  https://github.com/BlackDiverX/cqtools
</details>

<details>
  <summary>Matano: Open source security lake platform for AWS</summary>
  
 Matano is an open source security lake platform for AWS. It lets you ingest petabytes of security and log data from various sources, store and query them in an open Apache Iceberg data lake, and create Python detections as code for realtime alerting. Matano is fully serverless and designed specifically for AWS and focuses on enabling high scale, low cost, and zero-ops analysis of security logs. Matano deploys fully into your AWS account.

 https://github.com/matanolabs/matano
  
</details>

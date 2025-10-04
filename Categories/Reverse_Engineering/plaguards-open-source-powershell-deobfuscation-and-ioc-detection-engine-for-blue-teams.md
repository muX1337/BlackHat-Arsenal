# Plaguards: Open Source PowerShell Deobfuscation and IOC Detection Engine for Blue Teams.

## Description
Plaguards was developed to address a critical need within Incident Response (IR) teams, specifically in handling obfuscated PowerShell scripts—a frequent component in modern malware and ransomware attacks that severely threaten business operations. Despite the availability of numerous deobfuscation tools for JavaScript, there is a notable shortage of static deobfuscation resources for PowerShell, especially amidst the increasing trend of fileless PowerShell-based attacks observed throughout 2024. This gap has left IR teams without effective tools to manage these high-stakes threats.

Most existing tools only focus on detecting obfuscated PowerShell rather than fully deobfuscating it, leaving a crucial aspect of analysis unaddressed. Plaguards fills this void, enabling automated deobfuscation specifically tailored to PowerShell scripts. It empowers IR teams to swiftly parse through obfuscated lines, identify embedded Indicators of Compromise (IOCs) like IP addresses and URLs, and determine if they represent legitimate threats or false positives.

Beyond deobfuscation, Plaguards enhances the overall response workflow by providing templated PDF reports, documenting each deobfuscated line and cross-referencing IOCs with threat intelligence. This capability not only aids in real-time threat assessment but also supports IR teams by delivering comprehensive, actionable insights in a clear and organized format.

## Code
https://github.com/Bread-Yolk/plaguards

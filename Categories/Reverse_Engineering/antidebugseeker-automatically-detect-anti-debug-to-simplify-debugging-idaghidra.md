# AntiDebugSeeker: Automatically Detect Anti-Debug to Simplify Debugging (IDA/Ghidra)

## Description
Malware authors frequently use anti-debugging techniques to hinder analysis, making the malware either halt its actions or behave unusually upon detection by a debugger.

The complexity of these techniques varies, with malware spread through mass-mailing campaigns or ransomware often employing methods like VM detection, breakpoint detection, and time difference detection

to evade analysis, affecting a wide range of organizations.

"AntiDebugSeeker" is an open-source plugin for the binary analysis tools IDA and Ghidra, which are frequently utilized by analysts.

It streamlines the malware analysis process by automatically identifying the anti-debugging techniques embedded within Windows malware.

Code with anti-debug capabilities often overlaps with techniques used for anti-analysis, as well as with the preparatory steps forprocess injection, which are frequently employed by malware.

Therefore, by flexibly customizing the detection rules, it is possible not only to identify anti-debugging features but also to understand the functionalities of the malware.

Furthermore, the tool also provides functionalities to explain these anti-debugging measures and approaches to the corresponding functions.

This enhances the analyst's ability to understand and counteract the malware's evasion techniques effectively, offering a more comprehensive understanding and response strategy against such threats.

We will demonstrate malware analysis and explain how to use the tool's features, providing a practical understanding of how these features can be applied in actual threat scenarios.

## Code
https://github.com/LAC-Japan/IDA_Plugin_AntiDebugSeeker

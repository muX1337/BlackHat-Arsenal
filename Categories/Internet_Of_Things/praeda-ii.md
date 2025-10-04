# Praeda-II

## Description
Praeda - Latin for "plunder, spoils of war, booty". Praeda-II is a complete rewrite and update of the automated data/information harvesting tool Praeda that was originally released in 2014. Praeda-II is designed to conduct security audits on Multifunction Printer (MFP) environments.

Praeda-II leverages various implementation weaknesses and vulnerabilities found on multifunction printers (MFP) and extracts passwords such as Active directory credentials from MFP configurations including SMTP, LDAP, POP3 and SMB settings. The tool is designed to evaluate the MFP device configurations looking for certain setting that adversely impact the devices security posture. Also, the tools output logs are structured to be able to import into other tools such as Metasploit and to be easily parsable for quick identification of critical findings and reporting purposes.

During the demonstration, we will introduce everyone to the tool's framework structure, and show how new test modules and device fingerprinting can be easily added. We will walk all attendees through the various features and functions of this tool and explain how to effectively leverage it during internal penetrations testing, red team operations and blue team internal environment audits. This walkthrough of the tool will include examples, such as testing to gather credentials that can be used to gain access to critical internal systems, address book recovery containing account names and email address, and MFP device misconfigurations that impact an organization security posture.

## Code
https://github.com/percx/Praeda

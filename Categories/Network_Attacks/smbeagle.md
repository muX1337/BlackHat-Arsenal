# SMBeagle

## Description
SMBeagle is an SMB file share auditing and enumeration tool that rapidly hunts out file shares and inventories their contents. Built from a desire to find poorly protected files, SMBeagle casts the spotlight on files vulnerable to ransomware, watering hole attacks and which may contain sensitive credentials.

SMBeagle hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host?

Businesses of all sizes often have file shares with awful file permissions.

Large businesses have sprawling file shares and its common to find sensitive data with misconfigured permissions and small businesses often have a small NAS in the corner of the office with no restrictions at all!

SMBeagle crawls these shares and lists out all the files it can read and write. If it can read them, so can ransomware.

SMBeagle can provide penetration testers with the less obvious routes to escalate privileges and move laterally.

By outputting directly into elasticsearch, testers can quickly find readable scripts and writeable executables.

Finding watering hole attacks and unprotected passwords never felt so easy!

## Code
https://github.com/punk-security/smbeagle

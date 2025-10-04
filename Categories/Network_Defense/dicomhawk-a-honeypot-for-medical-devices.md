# DICOMHawk: a honeypot for medical devices

## Description
DICOM is a standard that is broadly used for the storage and transmission of medical devices. DICOM has been targeted by attackers with millions of patient record data being at risk. For instance, researchers in BlackHat Europe 2023 revealed security issues with DICOM that lead to more than 3,800 DICOM servers accessible via the internet with many leaking health and personal information.

In this arsenal presentation, we demonstrate DICOMHawk, an open-source python-based honeypot that is tailored for the DICOM protocol. With DICOMHawk we offer security practitioners and research a tool to be able to understand the attack landscape, lure attackers in, as well as understand Internet-level scanners such as Shodan. Among other properties, DICOMHawk offers various operations for a realistic DICOM server environment, the ability to comprehensively log DICOM associations, messages and events to understand incoming attacks, and a user-friendly web interface. Lastly, the honeypot is easily extendable via custom handlers.

## Code
https://github.com/honeynet/DICOMHawk

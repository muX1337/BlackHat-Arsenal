# The Only 'Kanvas' You Need When Responding to Security Incidents.

## Description
KANVAS is an open-source IR (Incident Response) case management tool with an intuitive desktop interface, built using Python. It provides a unified workspace for investigators working with SOD (Spreadsheet of Doom) or similar spreadsheets, enabling key workflows to be completed without switching between multiple applications. Kanvas supports many external lookups, making it easier to add context during investigations.

Some of the notable features include:

1. Built on the SOD (Spreadsheet of Doom): All data remains within the spreadsheet, making distribution and collaboration simple—even outside the application.
2. Attack Chain Visualization: Visualizes lateral movement for quick review of the adversary's attack path. Re-draw options allow the diagram to be displayed in multiple ways.
3. Incident Timeline: Presents the incident timeline in chronological order, helping investigators quickly understand the sequence and timing of events.
4. MITRE ATT&CK Mapping: Provides up-to-date MITRE tactics and techniques for mapping adversary activities.
5. MITRE D3FEND Mapping: Helps map defense strategies based on identified ATT&CK techniques. This is especially useful when responding to incidents from a defender's perspective.
6. VERIS Reporting: Offers an interface to track VERIS data, which can be shared post-incident with government entities and contribute to the Verizon Data Breach Investigations Report.
7. Markdown Editor: Provides an interface to create and update Markdown documents—ideal for note-taking or loading investigative playbooks.
8. STIX Export: Exports IOCs (Indicators of Compromise) in STIX 2.1 format, which can be easily imported into OpenCTI or MISP platforms.
9. Ransomware Victim Check: Verifies if a customer's or organization's data has been published online following a ransomware attack.
10. Bookmarks: Offers a curated list of security tools, an up-to-date list of Microsoft portal URLs, and the ability to create custom investigation-specific bookmarks.
11. Entra ID Reference: Provides a searchable list of known and malicious Microsoft Entra ID AppIDs—useful for investigating Business Email Compromise (BEC) cases.

Useful for:

1. Forensic Investigators
2. Incident Responders
3. Threat Hunters
4. SOC Analysts

## Code
https://github.com/WithSecureLabs/Kanvas

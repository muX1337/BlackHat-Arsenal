# CQURE Automatic Destinations Toolkit: Forensics, AppID Analysis & Jump List Reverse Engineering

## Description
The CQURE Automatic Destinations Toolkit is a forensic and research-grade collection of tools designed to analyze and interpret Windows Automatic Destinations (*. automaticDestinations-ms) files — a rich but underutilized source of timeline and user activity data. These binary files, associated with Jump Lists, contain detailed historical evidence of user interaction with applications and files. The tools are used internally by the CQURE Team in advanced forensics and have been developed based on real-world investigations requiring deep binary parsing and timeline construction from partially overwritten storage devices.

This toolkit enables analysts to calculate, identify, and resolve AppIDs used in Windows Jump Lists, decode file naming schemes based on process names or paths, and extract forensic details such as MAC addresses and hostnames from Automatic Destinations files. It also allows testers and researchers to simulate applications with arbitrary AppIDs and manipulate it. CQURE's reverse engineering of Automatic Destinations led to using in the toolkit some of the undocumented features that are not described in any of the books.

The toolkit enables analysts to:

1. Calculate, identify, and resolve AppIDs used in Jump Lists

2. Decode file naming schemes

3. Extract forensic details like MAC addresses and hostnames

4. Convert Jump List data into readable, structured XML and HTML

5. Simulate or register custom AppIDs for application behavior testing

6. Manipulate the content of Automatic Destinations

7. Automatically analyze all of the files during the analysis and generate a report to support forensics and incident response operations

How this is useful?

1. Provides deep insight into Jump List activity for timeline and usage analysis.

2. Helps correlate AppIDs with actual applications for investigative purposes.

3. Enables reverse engineering of forensic artifacts tied to user behavior.

4. Allows researchers to simulate or manipulate AppIDs, improving understanding of how Windows ties recent files to apps.

Why is this cool?

1. First toolkit combining AppID resolution, file name calculation, and file content decoding.

2. Supports both live system analysis and offline forensic workflows.

3. Provides a structured XML export of Jump List contents for automation and report building.

4. Helps answer key forensic questions like: "Which file was opened, when, and from where?"

Who is it for?

1. Forensic analysts

2. Threat hunters

3. Incident responders

4. Security researchers

5. Malware analysts

## Code
https://github.com/CQURE/CQTools

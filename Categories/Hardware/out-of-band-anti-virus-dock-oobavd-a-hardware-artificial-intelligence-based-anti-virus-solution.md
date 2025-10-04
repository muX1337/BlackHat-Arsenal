# Out-Of-Band Anti Virus Dock (OOBAVD) - A Hardware & Artificial Intelligence Based Anti Virus Solution

## Description
USB-based attacks account for more than 52% of all cybersecurity attacks on operational technology (OT) systems in the industrial control systems (ICS) industry. The discovery of Stuxnet in 2015 served as a stark reminder that even air-gapped computers, previously thought to be impervious to cyberattacks, are vulnerable. These systems are found in secure military organizations or Supervisory Control and Data Acquisition (SCADA) systems. The societal impact of such attacks can be enormous. Stuxnet, for example, caused significant damage to Iran's nuclear programs and facilities.

While air-gapped systems are considered "secure," they are inconvenient for computer operators, particularly when performing updates and transferring data, which require the use of mobile storage devices, such as USB sticks. Unfortunately, this introduces a flaw into the air-gapped systems, exposing them to computer viruses and malware. Furthermore, adding new peripherals to these systems, such as keyboards and mice, allows BadUSB attacks to be carried out.

OOBAVD is a solution to close this gap. OOBAVD acts as a intermediary between the air-gapped system and USB devices, scanning and blocking detected malicious files from the air-gapped system. Furthermore, malware can attack commercial software-based antivirus software on the host machine by blocking, corrupting, and replacing core antivirus engine files, rendering them inoperable and defenseless. OOBAVD being out of band in the transfer process, is mitigated from this risk.

OOBAVD is designed to have minimum software pre-installed, which reduces the attack surface area to be infected by malware. OOBAVD can also be wiped clean and flashed before connecting to new air-gapped computers, removing persistent malware that manages to infect OOBAVD.

## Code
https://github.com/FA-PengFei/OOBAVD_Pub

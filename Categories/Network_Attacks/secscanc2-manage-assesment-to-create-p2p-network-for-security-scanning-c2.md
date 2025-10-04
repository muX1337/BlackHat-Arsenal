# SecScanC2 -- Manage Assesment to Create P2P Network for Security Scanning & C2

## Description
In the realm of security attack and defense, as well as penetration testing, two key challenges often arise. Firstly, attack scanning is frequently detected by defensive security systems, resulting in the scanning IP being blocked. Secondly, when defensive assets are controlled and connected back to the command and control (C2) server, security devices may detect the connection, leading to countermeasures against penetration testers. To address these challenges and enable safe, efficient asset detection and secure connections to controlled assets, we have enhanced the Kademlia protocol and developed a Distributed Hash Table (DHT) technology.

Our hacking tool is highly effective during attack scanning, consisting of a large number of Internet nodes that dynamically update IDs and node tree structures at regular intervals. This approach allows each session to initiate requests from different nodes during the scanning process, thus avoiding IP blocking due to high-frequency scanning. Moreover, when connecting controlled assets back to the C2 server, nodes are randomly selected based on a user-defined hop count, effectively preventing penetration testers from being traced and significantly enhancing the stealthiness of the entire penetration testing process

## Code
https://github.com/T1esh0u/SecScanC2

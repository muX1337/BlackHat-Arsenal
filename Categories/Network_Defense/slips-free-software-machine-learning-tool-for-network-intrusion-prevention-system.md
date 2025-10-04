# Slips: Free software machine learning tool for Network Intrusion Prevention System

## Description
Slips is the first free software, behavioral-based, intrusion prevention system to use machine learning to detect attacks in the network. It is a modular system that profiles the behavior of devices and performs detections in time windows. Slips' modules detect a range of attacks both to and from the protected devices.

Slips detect attacks to and from devices protecting your network but also focusing on infected computers. All the analyses are reevaluated in time windows so computers can be unblocked if they are cleaned. Avoiding permanent detections when the risk is gone.

Slips manages Threat Intelligence feeds (44 external feeds, including our own), the enrichment with WHOIS/ASN/geo location/mac vendors. Allowing it to detect MITM attacks, scans, exfiltration, port scans, long connections, data uploads, unknown ports, connections without DNS, malicious JA3/JA3S, TLS certificates, etc.

An LSTM neural network detects C&C channels, a Random Forest is used to detect attacks on flows, and anomaly detection methods are used on the traffic. A final ML ensembling algorithm is used for blocking decisions and alert generation.

Slips reads packets from an interface, PCAPs, Suricata, Zeek, Argus and Nfdump. It generates alerts in text, json, and using the STIX/TAXII protocol, sending to CESNET servers using IDEA0 format, or to Slack.

Slips is the first IDS to use its own local P2P network to find other Slips peers and exchange data about detection using trust models that are resilient to adversarial peers.

The Kalipso Node.js and a Web interface allows the analysts to see the profiles' behaviors and detections performed by Slips modules directly in the console. Kalipso displays the flows of each profile and time window and compares those connections in charts/bars. It also summarizes the whois/asn/geocountry information for each IP in your traffic.

## Code
https://github.com/stratosphereips/StratosphereLinuxIPS

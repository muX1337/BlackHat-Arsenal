# Slips: A machine-learning based, free-software, P2P Network Intrusion Prevention System

## Description
For the last 7 years we developed Slips, a behavioral-based intrusion prevention system, and the first free-software network IDS using machine learning. Slips profiles the behavior of IP addresses and performs detections inside each time window in order to also *unblock* IPs. Slips has more than 20 modules that detect a range of attacks both to and from the protected device. It is an network EDR with the capability to also protect small networks.

Slips consumes multiple packets and flows, exporting data to SIEMs. More importantly, Slips is the first IDS to automatically create a local P2P network of sensors, where instances share detections following a trust model resilient to adversaries..

Slips works in several directionality modes. The user can choose to detect attacks coming *to* or going *from* these profiles, or both. This makes it easy to protect your network but also to focus on infected computers inside your network, which is a novel technique.

Among its modules, Slips includes the download/manage of external Threat Intelligence feed (including our laboratory's own TI feed), whois/asn/geocountry enrichment, a LSTM neural net for malicious behavior detection, port scanning detection (vertical and horizontal) on flows, long connection detection, etc. The decisions to block profiles or not are based on ensembling

algorithms. The P2P module connects to other Slips to share detection alerts.

Slips can read packets from the network, pcap, Suricata, Zeek, Argus and Nfdump, and can output alerts files and summaries. Having Zeek as a base tool, Slips can correctly build a sorted timeline of flows combining all Zeek logs. Slips can send alerts using the STIX/TAXII protocol.

Slips web interface allows to clearly see the detections and behaviors, including threat inteligence enhancements. The interface can show multiple Slips runs, summarize whois/asn/geocountry information and much more.

## Code
https://github.com/stratosphereips/StratosphereLinuxIPS

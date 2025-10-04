# KNX Bus Dump

## Description
KNX is a popular building automation protocol and is used to interconnect sensors, actuators and other components of a smart building together. Our KNX Bus Dump tool uses the Calimero java library, which we contributed to for the sake of this tool, to record the telegrams sent over a KNX bus. Particularly, our tool accesses the KNX bus through a TPUART connection but can be changed to use different connection mediums. The telegrams are dumped into a Wireshark-compatible hex dump file. Timestamps are provided and normalized to UTC time with nanosecond precision to perform data analysis and provide a timeline of the telegrams. The hex dump file can be imported into Wireshark, which can be configured to dissect the KNX telegrams with Wireshark's cEMI dissector.

Our tool can be used for protocol analysis of KNX sensors, actuators and other KNX devices. For example, we used the tool to understand our KNX devices and found irregular KNX telegrams. The tool is also ideal for security analysis of KNX devices given that it exposes all details of the involved protocol and data sent over the KNX bus.

Tcpdump and Wireshark cannot be used to dump telegrams sent over a KNX bus since we are dealing with native KNX telegrams, not TCP/IP packets. Wireshark and tcpdump can dump KNXnet/IP packets, which are TCP/IP packets. KNXnet/IP is a protocol for sending commands and data to a KNX bus over a TCP/IP network.

## Code
https://github.com/ChrisM09/KNX-Bus-Dump

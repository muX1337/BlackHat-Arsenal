# DataTrap - AI Based Data Driven Honeypot

## Description
We introduce DataTrap, an innovative and extensible honeypot system that emulates realistic behavior across TCP, HTTP, SSH, and various database protocols. Designed to simulate web applications, IoT devices, and databases, DataTrap goes beyond traditional honeypots by combining recorded payloads, metadata, and a large language model (LLM) to dynamically generate responses that closely mimic genuine application output.

This unique approach not only effectively deceives attackers but also delivers actionable insights—all while maintaining high performance, low cost of ownership, and operational efficiency. The system supports multiple applications and their different versions, and allows selective emulation of application components. Its modular architecture enables seamless extension of the network protocol layer to support additional applications and services over time.

At the heart of DataTrap is a continuously evolving dataset, which powers the LLM-based response generation. This dataset is central to the system's effectiveness and is actively maintained as part of the framework. LLM-generated responses are automatically integrated into the dataset, ensuring that the system adapts to emerging threats and stays up to date.

DataTrap is open-source, encouraging community contributions to enrich both the dataset and system capabilities. To simplify deployment, it is packaged as a Docker image, allowing users to run the honeypot system as a single container in any environment with minimal setup.

## Code
https://github.com/ThalesGroup/dd-honeypot

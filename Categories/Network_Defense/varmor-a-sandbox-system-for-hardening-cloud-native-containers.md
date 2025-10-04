# vArmor: A Sandbox System for Hardening Cloud-Native Containers

## Description
With the rise of cloud-native technologies, organizations are increasingly migrating critical business services to Kubernetes environments. Some are leveraging Kubernetes and Linux containers to create multi-tenant environments. Consequently, enhancing Linux container isolation, mitigating high-risk vulnerabilities, and defending against container environment infiltration have become focal points in cloud-native security.

In response to this growing need for security, our team has developed vArmor, a robust container sandbox solution tailored specifically for cloud-native environments. By leveraging technologies such as AppArmor LSM, BPF LSM, Seccomp, and Kubernetes Operator, vArmor abstracts the underlying complexities of AppArmor/BPF/Seccomp enforcers. This enables users to deploy and use vArmor seamlessly within their application ecosystem, enforcing access controls on container file access, process execution, network communication, system calls, and more.

vArmor supports the combination of multiple enforcers for Linux container protection. It offers various policy modes with dynamic updates, built-in rules, and customizable interfaces for access control in an "Allow by Default" manner. Additionally, it supports behavior modeling to collect container actions and generate models. Furthermore, it can enforce access control on containers in a "Deny by Default" manner based on behavior models.

With vArmor, securing your cloud-native applications is as straightforward as it gets. Say goodbye to complex security setups and hello to enhanced protection without compromising performance.

## Code
https://github.com/bytedance/vArmor

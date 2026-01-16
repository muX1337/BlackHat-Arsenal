# Beyond the Static rules: Cloud-Native Anomaly Detection with Kubescape

## Description
As cloud-native environments scale to hundreds or even thousands of microservices, maintaining effective runtime detection becomes one of the hardest problems in security engineering. Traditional rule-based tools like Falco and Tetragon require constant configuration and tuning. Static detection rules often fire on legitimate application behavior, leading to alert fatigue and ongoing investment in security tools. Any application update or deployment introduces new behaviors, forcing teams into an endless loop of manual exclusions.

Kubescape, a CNCF Incubating project with over 10k GitHub stars, brings a new approach. After four years of helping DevOps and DevSecOps teams with Kubernetes configuration scanning and vulnerability monitoring, Kubescape now introduces a powerful new capability: eBPF-based runtime anomaly detection.

This new feature minimizes operational fatigue by automatically learning the normal behavior of workloads and alerting only on deviations. Instead of relying on static rules, Kubescape builds per-application behavioral baselines. It captures process execution, file access, network activity, Linux capabilities, and system calls. These baselines are stored as native Kubernetes objects that are portable, auditable, and reusable across environments, enabling scalable detection and deep observability.

In this Arsenal session, we'll showcase real-world examples of how Kubescape detects anomalies with minimal configuration, contrast it with rule-based tools, and demonstrate how it integrates into existing DevSecOps workflows. Attendees will walk away with a powerful, community-driven, open-source weapon in their cloud-native defense arsenal backed by a welcoming community and four years of trust in production environments.

## Code
https://github.com/kubescape/kubescape

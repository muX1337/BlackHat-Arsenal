# The Eye of Falco: You can escape but not hide

## Description
Container technologies rely on features like namespaces, cgroups, SecComp filters, and capabilities to isolate different services running on the same host. However, SPOILER ALERT: container isolation isn't bulletproof. Similar to other security environments, isolation is followed by red-teamer questions such as, "How can I de-isolate from this?"

Capabilities provide a way to isolate containers, splitting the power of the root user into multiple units. However, having lots of capabilities introduces complexity and a consequent increase of excessively misconfigured permissions and container escape exploits, as we have seen in recently discovered CVEs.

Falco is a CNCF open source container security tool designed to detect anomalous activity in your local machine, containers, and Kubernetes clusters. It taps into Linux kernel system calls and Kubernetes Audit logs to generate an event stream of all system activity. Thanks to its powerful and flexible rules language, Falco will generate security events when it finds malicious behaviors as defined by a customizable set of Falco rules.

The recent Falco update introduced the feature to keep track of all the syscalls that may modify a thread's capabilities, modifying its state accordingly, allowing Falco to monitor capabilities assigned to processes and threads. This new feature allows users to create detection over those malicious misconfigurations and automatically respond by implementing actions to address the issue

In this talk, we explain how you can use Falco to detect and monitor container escaping techniques based on capabilities. We walk through show real-world scenarios based on recent CVEs to show where Falco can help in detection and automatically respond to those behaviors

https://falco.org/

## Code
https://github.com/falcosecurity/falco

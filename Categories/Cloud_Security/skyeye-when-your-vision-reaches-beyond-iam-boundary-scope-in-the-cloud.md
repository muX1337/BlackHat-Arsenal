# SkyEye: When Your Vision Reaches Beyond IAM Boundary Scope in the Cloud

## Description
Modern cloud environments demand a comprehensive understanding of IAM configurations across users, roles, groups, and the intricate web of inline and managed policies. Yet, as organizations scale their use of cloud technologies, the act of enumerating effective permissions and resource authorizations remains fraught with blind spots, especially when relying on traditional principal-specific enumeration tools and frameworks. When a single set of credentials lacks the necessary permissions, or when multiple principals operate in isolation, cloud penetration testers are left with an incomplete and fragmented IAM landscape, resulting in hidden privilege escalation vectors, undetected misconfigurations, and weakened compliance postures.

However, is a principal-centric enumeration strategy sufficient for reconnaissance in adversary simulation or defense? Our research suggests not. The inability to correlate and chain disparate IAM permissions across multiple principals leads to critical false negatives and gaps in situational awareness - the gaps that threat actors are increasingly adept at exploiting.

In this Arsenal session, we will showcase a new framework: SkyEye - The First Cooperative Multi-Principal IAM Enumeration Framework for AWS Cloud. SkyEye Framework proposed and developed two novel models: the Cross-Principal IAM Enumeration Model (CPIEM) and the Transitive Cross-Role Enumeration Model (TCREM). Unlike conventional tools and frameworks, SkyEye is able to synchronize reconnaissance across multiple user and role sessions, dynamically chaining and merging their vantage points to unravel the full spectrum of permissions, resource authorizations, and hidden escalation paths. This methodology exposes not only what each principal can see, but also what they can achieve in combination, surfacing privilege chains and attack paths invisible to siloed IAM enumeration.

SkyEye is further powered by an extensible dataset mapping AWS actions to MITRE ATT&CK Cloud - TTPs, alongside with severity ratings, adversarial abuse methodologies, and real-world threat actor behaviors. This enables immediate translation of raw IAM data into valuable information for red teaming and cloud defense.

Join us to see how SkyEye sets a new standard for cloud reconnaissance to improve cloud adversary simulation and detection engineering. Witness how cooperative multi-principal IAM enumeration can transform your reconnaissance of AWS permissions, and why a truly complete IAM picture is only viable when principals cooperate together.

## Code
https://github.com/0x7a6b4c/SkyEye

# SharpSCCM

## Description
SharpSCCM is an open-source C# utility for interacting with SCCM, inspired by the PowerSCCM project by @harmj0y, @jaredcatkinson, @enigma0x3, and @mattifestation. This tool can be used to demonstrate the impact of configuring SCCM without the recommended security settings, which can be found here: https://docs.microsoft.com/en-us/mem/configmgr/core/clients/deploy/plan/security-and-privacy-for-clients

Currently, SharpSCCM supports the NTLMv2 coercion attack techniques noted in this post (https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a), as well as the attack techniques noted in this post (https://enigma0x3.net/2016/02/29/offensive-operations-with-powersccm/), which have been modified to coerce NTLMv2 authentication rather than running PowerShell on the target. SharpSCCM can also be used to dump information about the SCCM environment from a client, including the plaintext credentials for Network Access Accounts.

Research is ongoing to add SharpSCCM features to:
- pull and decrypt Network Access Account credentials from SCCM servers using a low-privileged account on any client machine
- execute actions in SCCM environments that require PKI certificates to secure client/server communications
- escalate privileges from local administrator on site servers to SCCM Full Administrator

## Code
https://github.com/Mayyhem/SharpSCCM

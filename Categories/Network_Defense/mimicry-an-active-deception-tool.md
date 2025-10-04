# Mimicry: An Active Deception Tool

## Description
In incident response scenarios, intercepting attacks or quarantining backdoors is a common response technique. The adversarial active defense will immediately make the attacker perceive that the intrusion behavior is exposed, and the attacker may try to use defense evasion to avoid subsequent detection. These defense evasion may even result in later attacks going undetected. If we mislead or deceive the attacker into the honeypot, we can better consume the attacker's time cost and gain more response time.

We invented a series of toolkits to deceive attackers during the "kill-chain" . For Example:

Exploitation:
1. We return success and mislead the attacker into the honeypot for brute-force attacks.
2. We will simulate the execution of web attack payloads to achieve the purpose of disguising the existence of vulnerabilities in the system.

Command & Control:
1. For the Webshell scenario, we will replace the Webshell with a proxy and transfer the Webshell to the honeypot. When the attacker accesses Webshell, the proxy will forward his request to the honeypot.
2. For the reverse shell, we will inject the shell process and forward the attacker's operation to the shell process in the honeypot.
3. For the backdoor, we will dump the process's memory, resources, etc., and migrate it to the honeypot to continue execution.

## Code
https://github.com/chaitin/Mimicry

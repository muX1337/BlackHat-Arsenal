# SSHook: A Lightweight Syscall Hooking Tool for Uncovering Hidden Malicious Instructions

## Description
Most Android hook ways aim at watching APIs for Java or Native code. However, some malicious apps try to escape hooking and access sensitive data using syscall directly, so it is crucial in order to uncover hidden code that some malicious apps use to bypass standard hooking techniques and access sensitive data directly through system calls. We have implemented a syscall hooking tool based on Seccomp-BPF named SSHook, which gives better balance between performance and compatibility.

Seccomp-BPF was introduced into Linux kenel to filter syscalls and their arguments, we transform this security feature into a syscall hook framework which support devices range from Android 8.1 to Android 13. Our tool SSHook combined Seccomp-BPF with throwing an exception to catch syscall, and resuming instructions for normal execution by preparing additional threads earlier, which avoids frequent interruptions and possible risks like deadlocks, suspensions, or crashes. For performance improvement, we have implemented a flag that determines whether to resume execution using either the inactive parameter or the higher 4 bytes of an integer type, but the program can still run normally without any impact. Besides, SSHook is a lightweight framework but performs efficiently and robustly compared with other invasive or complicated solutions, which keep stable and reliable by standing on the shoulders of kernel features.

SSHook can help to identify suspicious behavior in malicious Apps which abuse syscall to steal privacy files or collect sensitive data like MAC, applist, which can be integrated into sandbox environment to conduct more complete dynamic analysis. Furthermore, SSHook allows us to replace syscall arguments and bypass hooking tools to evade detection, which is particularly useful in preventing the collection of device fingerprints and protecting user privacy against tracking.

## Code
https://github.com/bytedance/bhook

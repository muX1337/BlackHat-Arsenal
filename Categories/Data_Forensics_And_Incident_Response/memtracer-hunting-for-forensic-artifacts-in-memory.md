# MemTracer: Hunting for Forensic Artifacts in Memory

## Description
MemTracer is a tool that offers live memory analysis capabilities, allowing digital forensic practitioners to discover and investigate stealthy attack traces hidden in memory.

Advanced persistence threat (APT) adversaries use stealthy attack tactics that only leave volatile short-lived memory evidence. The reflective Dynamic-Link Library (DLL) load technique is considered one of the stealthiest attack techniques. Reflective DLL load allows adversaries to load malicious code directly into memory, rather than loading a file from the disk. Thus, reflective DLL load leaves no digital evidence present on the disk. The malicious DLL continues to execute as long as the compromised process is running. Terminating a compromised process leads to the removal of the malicious DLL from memory, and the release of the memory region back to the pool for reallocation. Therefore, memory needs to be examined periodically in order to detect the existence of a malicious DLL that loaded reflectively into memory.

Loading DLL reflectively produces an unusual memory region’s characteristics that can indicate its existence. The MemTracer tool was developed to efficiently scan memory regions to detect reflective DLL loading symptoms. Mainly, MemTracer aims to detect native .NET framework DLLs that are loaded reflectively. Additionally, MemTracer provides the ability to search for a specific loaded DLL by name, which can retrieve the list of processes that have abnormally loaded the specified module for further investigation.

## Code
https://github.com/kristopher-pellizzi/MemTrace

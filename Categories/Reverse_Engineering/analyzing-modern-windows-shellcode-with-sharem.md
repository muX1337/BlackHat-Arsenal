# Analyzing Modern Windows Shellcode with SHAREM

## Description
Shellcode is omnipresent, a constant part of the exploitation and malware ecosystem. Injected into process memory, there are limitless possibilities. Yet until recently, analysis techniques were severely lacking. We present SHAREM, an NSA-funded shellcode analysis framework with stunning capabilities that will revolutionize how we approach the analysis of shellcode.

SHAREM can emulate shellcode, identifying more than 25,000 WinAPI functions as well as 99% of Windows syscalls. This emulation data can also be ingested by its own custom disassembler, allowing for functions and parameters to be identified in the disassembly for the first time ever. The quality of disassembly produced by SHAREM is virtually flawless, markedly superior to what is produced by leading disassemblers. In comparison, IDA Pro or Ghidra might produce a vague "call edx," as opposed to identifying what specific function and parameters is being called, a  highly non-trivial task when dealing with shellcode.

One obstacle with analyzing shellcode can be obfuscation, as an encoded shellcode may be a series of indecipherable bytes�a complete mystery. SHAREM can easily overcome this, presenting the fully decoded form in the disassembler, unlocking all its secrets. Without executing the shellocode, emulation can be used to help fully deobfuscate the shellcode. In short, a binary shellcode � or even the ASCII text representing a shellcode � could be taken and quickly analyzed, to discover its true, hidden functionality.

One game-changing innovation is complete code coverage. With SHAREM, we ensure that all code is executed, capturing function calls and arguments that might otherwise be impossible to get. This is done by taking a series of snapshots of memory and CPU register context; these are restored if a shellcode ends with unreached code. In practical terms, this means if a shellcode ordinarily would prematurely terminate, we might miss out several malicious functions. Complete code coverage allows us to rewind and restart at specific points we should not be able to reach, discovering all functionality.

SHAREM will now integrate AI to help resolve what exactly is going on. The enumerated APIs and parameters can be analyzed to identify malicious techniques, which could be found in MITRE ATT&CK framework and elsewhere. This helps reduce the human analysis effort required. Additionally,

SHAREM can use AI to rename functions based on functionality. AI is also used to provide detailed text descriptions of how each WinAPI or syscall is used within the shellcode, especially as it pertains to MITRE. There is much more to be seen with the new AI-enhanced capabilities.

The ease and simplicity of SHAREM is breathtaking, especially comparison to how much time and effort similar analysis would require otherwise. SHAREM represents a major shift in our capability to analyze shellcode in a highly efficient manner, documenting every possible clue � whether it be functions, parameters, secrets, or artifacts.

For reverse engineers of all kinds, SHAREM is a must-see presentation.

## Code
https://github.com/Bw3ll/sharem

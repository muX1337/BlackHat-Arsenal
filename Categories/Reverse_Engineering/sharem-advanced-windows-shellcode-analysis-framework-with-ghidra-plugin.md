# SHAREM: Advanced Windows Shellcode Analysis Framework with Ghidra Plugin

## Description
Shellcode can be cryptic, especially when encoded. Understanding its functionality is not straightforward. SHAREM is a cutting-edge Shellcode Analysis Framework, with both emulation and its own disassembler. SHAREM's unprecedented capabilities can allow us to unravel the mysteries of shellcode in new ways not seen.

Windows syscalls have become trendy in offensive security, yet SHAREM is the only tool that can emulate and log all user-mode Windows syscalls. Additionally, SHAREM also emulates and logs thousands of WinAPI functions. SHAREM is the only shellcode tool to parse and discover not only parameters, but also entire structures passed as parameters. SHAREM doesn't present parameters as hexadecimal values, but converts each to human readable format, in vivid colors.

Disassemblers like IDA Pro and Ghidra can be poor at disassembling shellcode accurately. SHAREM's disassembler is significantly more accurate with its original analysis capabilities. SHAREM additionally can uniquely integrate emulation results to provide flawless disassembly. Novel signature identifications are used to identify each function in the shellcode, and parameter values. SHAREM uses unique capabilities to accurately identify data, presenting data the correct way, not as misinterpreted instructions. SHAREM also uniquely provides complete-code coverage via emulation, capturing all functionality.

New at Arsenal, we will release a new script that allows SHAREM's output to be ingested by Ghidra. While Ghidra can handle shellcode in some cases, it simply cannot beat a framework specifically designed to handle and emulate shellcode. As such, this new release leverages SHAREM's advanced capabilities. Additionally, major updates include revamped complete-code coverage, timeless debugging of stack, nearly doubling the number of supported WinAPIs.

SHAREM provides unprecedented capabilities with encoded shellcode. Not only does it fully deobfuscate shellcode through emulation, discovering WinAPIs and syscalls, but it automatically recovers the shellcode's deobfuscated form. SHAREM presents error-free disassembly of its decoded form, with function calls and parameters labelled.

## Code
https://github.com/Bw3ll/sharem

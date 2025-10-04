# Unravelling the Mysteries of Shellcode with SHAREM: A Novel Emulator and Disassembler for Shellcode

## Description
Shellcode can be highly cryptic; comprehending its functionality is not straightforward; shellcode may be bewildering, especially if encoded. SHAREM is a cutting-edge Shellcode Analysis Framework, with both emulation and its own disassembler. In this talk, we explore SHAREM's powerful, unique capabilities, to unravel the mysteries of shellcode.

Windows syscalls have become trendy in offensive security, and SHAREM is the only tool that can emulate and log all user-mode Windows syscalls. Additionally, SHAREM also emulates and logs more than 16,000 WinAPI functions. SHAREM is the only shellcode tool to parse and discover not only parameters, but also structures passed as parameters, displaying all structure fields to users. SHAREM doesn't present parameters as hexadecimal values, but converts each to human readable format, in vivid colors.

Disassemblers like IDA Pro and Ghidra often are poor at disassembling shellcode accurately. SHAREM's disassembler is significantly more accurate with its original analysis capabilities. SHAREM additionally can uniquely integrate emulation results to provide flawless disassembly. Novel signature identifications are used to identify each function in the shellcode, along with parameter values. SHAREM uses unique capabilities to accurately identify data, presenting data the correct way, not as misinterpreted Assembly instructions.

SHAREM provides unprecedented capabilities with encoded shellcode. Not only does it fully deobfuscate shellcode through emulation, discovering both WinAPIs and syscalls, but it automatically recovers the shellcode's deobfuscated form. SHAREM presents error-free disassembly of its decoded form, with function calls and parameters labelled.

SHAREM provides other features to better understand shellcode. SHAREM's complete-code coverage ensures that no functionality is missed. Timeless debugging lets users unwind a complex shellcode, seeing hundreds of thousands of instructions executed and the CPU state before and after each. SHAREM also outputs to JSON format; while ideal for individual users, SHAREM can be deployed as part of automated web services. SHAREM is a game-changer.

## Code
https://github.com/bw3ll/sharem

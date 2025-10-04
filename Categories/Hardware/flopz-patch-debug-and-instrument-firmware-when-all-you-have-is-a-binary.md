# Flopz: Patch, Debug and Instrument Firmware When All You Have Is a Binary

## Description
Embedded systems can be challenging to analyze. Especially on automotive systems, many things that we take for granted in other scenarios such as debugging and tracing can not always work. On some systems, hardware debugging resources are locked or used for something else, and sometimes they don't even exist at all!

Assuming that code can be dumped, the solution for this can be emulation, however emulating a rich embedded system can be painful and many times, only few aspects of the system can be sufficiently modeled. For some systems, it can be challenging to determine the environmental factors that influence whether the device behaves correctly or not.
What if there was an in-between? How can we debug, fuzz, and tamper embedded firmware without access to hardware debugging or emulation?

This is why we've created Flopz. Using Flopz, you can easily cut, patch, and instrument firmware in order to reverse engineer and attack all kinds of embedded devices. Flopz is a new, open-source, pythonic assembler toolkit for instrumenting firmware binaries and generating modular shellcode.

The tool does not require source code access and it does not require a working compiler toolchain either.

Combined with Ghidra, we show a simple but smart binary instrumentation method and a pythonic assembler to automatically patch large firmware binaries, enhancing them with interactive backdoors, as well as function- or basic-block trace capabilities. Showcasing a demo on a real-world device, we demonstrate how Flopz works and how it supports many popular embedded architectures such as RISC-V, ARM Thumb Mode and PowerPC VLE.

## Code
https://github.com/Flopz-Project/flopz

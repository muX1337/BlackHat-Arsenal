# GDBFuzz: Embedded Fuzzing with Hardware Breakpoints

## Description
In this tool demo, we will present GDBFuzz, a new open source fuzzer that leverages hardware breakpoints and program analysis to test embedded systems. Existing fuzzers for embedded devices most often run on an emulation of the code, but GDBFuzz runs on the device itself. This allows GDBFuzz to fuzz devices which do not have emulations. Its integration with Ghidra allows it to fuzz closed-source applications. All the tool needs is access to the commonly used GDB remote protocol.

We will explain how GDBFuzz combines hardware breakpoints with control flow relationships to guide fuzzing exploration. We will also detail its underlying analyses and techniques that were recently published at the academic conference ISSTA. GDBFuzz detected three previously unknown bugs in open-source embedded software that were confirmed by the vendors. GDBFuzz is the first tool allowing to fuzz embedded systems at scale.

To demonstrate the fuzzer's ease of use and efficiency, we will run an interactive demo on multiple devices (including ARM and MSP430 processors). At the end of the session, attendees will know how to use GDBFuzz to test their own embedded systems.

## Code
https://github.com/boschresearch/gdbfuzz

# rev.ng decompiler

## Description
rev.ng is a static binary analysis framework based on LLVM and QEMU.

Key features:

* Full-fledged decompiler, that emits syntactically valid C.

* Large architecture support (x86-64 x86, ARM, AArch64, MIPS and s390x).

* Ideal environment for deobufscation thanks to the off-the-shelf availability of the LLVM -O2 optimization pipeline.

* Support for static code analysis using symbolic execution (KLEE or clang-static-analyzer) or CodeQL.

* Automatic recovery of data structures exploiting information across the whole program.

* Scripting interface for Python and TypeScript.

## Code
https://github.com/revng/revng

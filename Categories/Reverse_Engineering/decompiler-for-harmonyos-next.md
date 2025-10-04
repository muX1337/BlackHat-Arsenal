# Decompiler for HarmonyOS NEXT

## Description
HarmonyOS NEXT is the next generation operating system developed by Huawei. It completely removes the Android AOSP code and is incompatible with Android applications. In addition, it has developed a new operating system kernel, which will cover more than one billion devices in the future. Because HarmonyOS NEXT has a new compiler, interpreter, file format and instruction set architecture, it makes the previous program analysis tools invalid. In addition, the information and documents of the new system are very limited, which makes it difficult for security analysts to conduct security analysis and risk assessment quickly and effectively.

To solve this problem, we read the source code of ArkCompiler, the compiler of HarmonyOS NEXT. We summarized the detailed process of ArkCompiler compilation. It takes arkTS (a variant of typescript) as input, translates it into Panda Bytecode, and finally executes it in the ecma virtual machine. It is also designed to support JIT and AOT functions. In addition, we also have a deep understanding of its AST, IR, assembly, executable files, and the design ideas of compilation optimization design.

Based on this, we developed the ArkCompiler decompilation tool named arkdecompiler, which takes Panda Binary File as input, parses Panda Bytecode, and then translates it into Panda IR. After having IR, we can do various analyses. Based on IR, we reversely construct the native arkTS AST tree, and then we traverse the AST tree and translate it into native arkTS source code. At present, we have implemented support for common binary operation instructions.

To be more specifically, we will talk about:

- ArkCompiler's overall process and key components such as AST, IR, bytecode.

- How to translate Panda Bytecode into Panda IR using existing components of ArkCompiler.

- How to automatically reverse build the ArkTS AST tree based on Panda IR.

- After having the AST tree, how do we convert it into ArkTS source code.

In order to demonstrate the capabilities of our framework and tools, we prepared some cases, including a demo written in arkTS, compiled into Panda Bytecode using ArkCompiler, and restored to native ArkTS code using our tool Arkcompiler.

In order to allow more people to participate, quickly improve the project and make it more powerful, so as to improve the efficiency of security analysts, we will release the source code of the tool. In the future, we hope that our work can make the HarmonyOS system and its applications more secure.

## Code
https://github.com/jd-opensource/arkdecompiler

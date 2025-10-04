# .NET Unpacking: When Frida Gets the JIT out of It

## Description
.NET-based malware families (like AgentTesla, CrimsonRat, and MassLogger, to list a few) can include obfuscation or packing that would harden analysts' work to understand and mitigate these threats effectively. Several options exist for researchers to tackle this challenge such as (but not limited to ) De4Dot, JITM (Mandiant 2020), DotDumper (Black Hat 2022), or JitHook (JSAC 2023) ... However, those solutions either don't cover the case where CLR APIs are intercepted by the packer, or do it in a very limited way. Our new tool has been developed to address this issue, adding some notable advancements that hopefully will prove its utility in the field of malware analysis.

Our Frida-Jit-unPacker (FJP) tool uses a passive, less intrusive approach than previous tools, making it less likely to be detected by anti-unpacking-features. It is developed using Python3 and Frida and doesn't impose restrictions on the .NET framework version associated with the sample. The tool is not focused on specific packers, making it generic and flexible.

One of its improvements compared to previously listed tools is its ability to also recover and fix original tokens from encrypted ones.

In addition, this tool employs several strategies to be more covert in its operations compared to existing solutions. It achieves this by focusing on intercepting lower-level functions, less likely to set off anti-unpacking mechanisms typically employed by packers. This stealthy approach is further enhanced by disassembling the Common Language Runtime (CLR) - strategically placing hooks just before or after likely monitoring points, tactically reducing the chances of triggering packers' anti-unpacking mechanisms.

These enhancements aim to assist analysts and researchers in the evolving 'cat and mouse' game of malware code protection. Hopefully, the tool will prove to be a valuable addition to the researchers' arsenal.

## Code
https://github.com/imperva/frida-jit-unpacker

# Mothra: A Ghidra EVM Extension

## Description
Recent years have witnessed the rise of cyber-attacks targeting Ethereum and EVM-based blockchains. Many of these attacks have involved the deployment of malicious EVM-compatible smart contracts to facilitate the hacks. One notable example is the use of "callee" smart contracts in flash loan attacks, which have resulted in substantial financial losses since early 2020. These malicious smart contracts are typically scripted in high-level languages (e.g., Solidity and Vyper), compiled into EVM bytecode, and deployed by bad actors without source code verification, making forensic analysis challenging.

To better understand the malicious smart contracts, EVM decompilers (e.g., EtherVM [1], Dedaub [2]) are commonly used by security researchers to convert EVM bytecode into high-level languages. However, the lack of interactive functionalities on existing decompilers makes comprehensive analysis difficult. Specifically, these tools do not allow for illustrating control flow graphs, adding comments, patching contract bytecode, and other interactive features. Notably, IDA Pro [3] and Ghidra [4], renowned for their robust interactive user interfaces and reverse engineering capabilities within the security research community, do not inherently support EVM. While plugins like the IDA EVM plugin [5] and Ghidra EVM plugin [6] have been developed to bridge this gap, they still have limitations, such as incomplete support for the 256-bit machine word size and limited decompilation capabilities.

We present Mothra, a Ghidra extension designed to address the aforementioned limitations. By integrating with Ghidra, Mothra facilitates the disassembly, CFG visualization, and decompilation of smart contracts. Moreover, Mothra analyzes EVM bytecode to uncover the internals of smart contract such as smart contract metadata, external functions, function signatures, and calling references of internal functions. This empowers Ghidra with enhanced functionality tailored for reverse engineering EVM-based smart contracts.

## Code
https://github.com/syjcnss/Mothra

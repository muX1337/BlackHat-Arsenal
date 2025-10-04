# Revela: Unlock the Secrets of Move Smart Contracts

## Description
Powered by the secure and robust Move language, emerging blockchains like Aptos and Sui are gaining rapid popularity. However, their increasingly complex smart contracts, which are often entrusted with valuable assets, need to provide users with the ability to verify the code safety. Unfortunately, it has become common for Move-based protocols to be deployed solely in low-level bytecode form, without accompanying source code. Therefore, reconstructing the original source of the on-chain contracts is essential for users and security researchers to thoroughly examine, evaluate and enhance security.

This talk introduces Revela, the first-ever open-source tool designed to decompile Move bytecode back to its original source code, empowering users and researchers with newfound transparency. We will explain how our tool leverages advanced static analysis techniques to recover the original source code structure, including modules, functions, and data types.

The presentation will include some live demonstrations of using Revela to decompile Move bytecode from online transactions. Additionally, we will showcase how our decompiler can be utilized to uncover vulnerabilities in closed-source protocols running on Aptos and Sui blockchains.

## Code
https://github.com/verichains/revela

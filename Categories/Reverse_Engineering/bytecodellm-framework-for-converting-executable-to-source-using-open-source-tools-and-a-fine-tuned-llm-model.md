# ByteCodeLLM - Framework for Converting Executable to Source using Open-source Tools and a Fine-tuned LLM Model

## Description
In this talk, we will present a proof of concept for ByteCodeLLM, a tool designed to convert obfuscated or closed-source Python EXEs back into their original source files.

Leveraging a fine-tuned Large Language Model (LLM), ByteCodeLLM offers accurate decompilation of newer Python versions such as 3.8 through 3.12.

Step 1: Extraction and Decompilation

Python EXEs are first extracted into .pyc and .pyd files using open-source tools like PyInstXtractor.

PyCDC and PyCDAS are utilized to decompile .pyc files into partially decompiled .py format and extract the byte code representation.

Step 2: Byte code to source code using a Fine-tuned LLM Model

ByteCodeLLM's model is trained on a vast dataset of Python projects and fine-tuned to provide accurate decompilation.

Using Ollama, users can host the LLM both locally and remotely. By calling the Ollama API, the partially decompiled Python files and their byte code are sent for processing

and generated into complete, accurate, and well-formatted source files.

ByteCodeLLM currently targets Python EXEs but can potentially be extended as a future framework for decompiling other byte code / virtual machine based programming languages and provides an easy-to-use command-line interface.

## Code
https://github.com/cyberark/ByteCodeLLM

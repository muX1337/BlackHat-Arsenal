# promptmap

## Description
Prompt injection is a type of security vulnerability that can be exploited to control the behavior of a ChatGPT instance. By injecting malicious prompts into the system, an attacker can force the ChatGPT instance to do unintended actions.

promptmap is a tool that automatically tests prompt injection attacks on ChatGPT instances. It analyzes your ChatGPT rules to understand its context and purpose. This understanding is used to generate creative attack prompts tailored for the target. promptmap then run a ChatGPT instance with the system prompts provided by you and sends attack prompts to it. It can determine whether the prompt injection attack was successful by checking the answer coming from your ChatGPT instance.

## Code
https://github.com/utkusen/promptmap

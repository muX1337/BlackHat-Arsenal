# VelLMes, a high-interaction AI based deception framework.

## Description
VelLMes is the first free-software AI-based deception framework that can create digital-twins of Linux shells (SSH), SMTP, POP, HTTP and MYSQL protocols.

It is based on new deception research that uses fine-tuned and trained LLMs to create high-interaction honeypots that look exactly like your production servers. When attackers connect to a VelLMes SSH, they can not distinguish it from a real Linux shell. The LLM creates in real time, and depending on the commands of the attacker, the complete structure of the simulated computer, including file contents, output of all commands, connection to the Internet (simulated), users, and more.

VelLMes key features are:

The content from a previous session can be carried over to a new session to ensure consistency.

It uses a combination of techniques for prompt engineering, including chain-of-thought.

Uses prompts with precise instructions to address common LLM problems.

More creative file and directory names for Linux shells

In the Linux shell the users can "move" through folders

Response is correct also for non-commands for all services

It can simulate databases and their relations in the MySQL honeypot.

It can create emails with all the necessary header info in the POP3 honeypots.

It can respond to HTTP GET requests

VelLMes was evaluated and tested in its generative capabilities and deception capabilities with human penetration tester professionals to see if they can recognize the honeypot. Most attackers do not realize this is deception, and it performs much better than other deception technologies we have compared against.

VelLMes can bring a new perspective to your deception technology in your company.

## Code
https://github.com/stratosphereips/VelLMes-AI-Deception-Framework

# MIPSEval: Multi-turn LLM Evaluation of LLM Safety

## Description
Creating malicious and vulnerable code and harmful content has become easier with LLMs becoming publicly available. Even though the developers of cloud and most local LLMs are taking care to implement ethical guidelines and safety guardrails in their models, to make them refuse malicious content generation, malicious actors are still finding ways to elicit unwanted behaviors from LLMs. The malicious actors often use various jailbreaking or prompt injection techniques and their combination to achieve the desired result.

For this reason, it is important to constantly improve the safety of LLMs, both base models and applications using them. And in order to achieve better safety, we need to be able to evaluate LLMs thoroughly and constantly. The safety evaluation of LLMs should be easily runnable and automated as much as possible so that every change in the model or the LLM's system prompt can be evaluated quickly and precisely.

We present MIPSEval, a Multi-turn Injection Planning System for LLM Evaluation. It is a free-software LLM-based tool that uses genetic algorithms and reinforcement learning to evaluate the safety of LLMs against various jailbreaking/prompt injection techniques.

MIPSEval is the result of our experience as finalists in the Amazon Nova Trusted AI challenge.

Current human attacks against LLMs today do not rely on one prompt but include gradual attempts to elicit harmful behavior over multiple prompts in the conversation. The conversation can include jailbreaks combined with malicious as well as benign requests. MIPSEval uses LLM-guided genetic algorithms to evolve new multi-turn attack strategies, based on its previous attempts. MIPSEval has an internal multi-LLM agentic architecture to generate and execute attack strategies against the target LLM application that is being evaluated.

To the best of our knowledge, MIPSEval is the first tool that uses multi-LLM agentic genetic-based architectures to design and automatically execute a conversation attack strategy. The strategies can be further updated by MIPSEval based on the ongoing conversation, meaning the steps not executed yet can be changed.

The MIPSEval tool was tested against cloud models from OpenAI and local models run via Ollama. It successfully generated strategies that elicit unsafe behavior from all the LLMs it was tested against.

## Code
https://github.com/stratosphereips/MIPSEval

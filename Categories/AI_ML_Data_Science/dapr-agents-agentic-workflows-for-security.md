# Dapr Agents: Agentic Workflows for Security

## Description
Agentic workflows represent a new frontier in how AI systems operate, moving beyond simple task completion toward iterative, dynamic processes. Unlike zero-shot prompting, where an LLM completes a single task in isolation, agentic workflows incorporate loops, branching decisions, and continuous refinement, making them particularly effective for complex domains like cybersecurity. Security workflows often demand more than linear task execution—they require sophisticated orchestration, adaptability, and collaboration between tools, agents, and functions to address challenges like incident investigation or attack path traversal.

In this talk, I will introduce Floki, an open-source framework designed to simplify the creation and orchestration of agentic workflows. Built on Dapr, Floki provides a powerful platform for researchers and developers to experiment with LLM-based autonomous agents. It enables agents to function as independent, self-contained units using Dapr's Virtual Actor pattern, eliminating concurrency concerns while seamlessly integrating into larger workflows. Floki also supports collaboration through Pub/Sub messaging, allowing agents to communicate efficiently and work together toward shared goals.

Using real-world security examples, we will explore how Floki facilitates deterministic and non-deterministic workflows, event-driven interactions, and chat-based agentic collaboration. From task chaining to fan-out/fan-in patterns, I'll demonstrate how Floki empowers researchers and practitioners to design and deploy agentic workflows that address the unique challenges of cybersecurity operations. This talk aims to provide both conceptual insights and practical guidance for advancing research and implementation in multi-agent systems.

## Code
https://github.com/Cyb3rWard0g/floki

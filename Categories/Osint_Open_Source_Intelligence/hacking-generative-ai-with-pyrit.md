# Hacking generative AI with PyRIT

## Description
In today's digital landscape, generative AI (GenAI) systems are ubiquitous, powering everything from simple chatbots to sophisticated decision-making systems. These technologies have revolutionized our daily interactions with digital platforms, enhancing user experiences and productivity. Despite their widespread utility, these advanced AI models are susceptible to a range of security and safety risks, such as data exfiltration, remote code execution, and the generation of harmful content. Addressing these challenges, PyRIT (Python Risk Identification Toolkit for generative AI), developed by the Microsoft AI Red Team, stands out as a pioneering tool designed to identify these risks associated with generative AI systems.

PyRIT empowers security professionals and machine learning engineers to proactively identify risks within their generative AI systems, enabling the assessment of potential risks before they materialize into real-world threats. Traditional methods of manual probing for uncovering vulnerabilities are not only time-consuming but also lack the precision and comprehensiveness required in the fast-evolving landscape of AI security. PyRIT addresses this gap by providing an efficient, effective, and extensible framework for identifying security and safety risks, thereby ensuring the responsible deployment of generative AI systems. It is important to note that PyRIT is not a replacement for manual red teaming of generative AI systems. Instead, it enhances the process by allowing red team operators to concentrate on tasks that require greater creativity. PyRIT helps to assess the robustness of these generative AI models against different responsible AI harm categories such as fabrication/ungrounded content (e.g., hallucination), misuse (e.g., bias), and prohibited content (e.g., harassment).

By the end of this talk, you will understand the presence of security and safety risks within generative AI systems. Through demonstrations, I'll show how PyRIT can effectively identify these risks in AI systems, including those based on text and multi-modal models. This session is designed for security experts involved in red teaming generative AI models and for software/machine learning professionals developing foundational models, equipping them with the necessary tools to detect security and safety vulnerabilities.

Key Features of PyRIT include:

1.	Scanning of GenAI models utilizing prompt injection techniques.

2.	Support for various attack strategies, including single-turn and multi-turn engagements.

3.	Compatibility with Azure OpenAI LLM endpoints, enabling targeted assessments. Easy to extend to custom targets.

4.	Prompt Converters: Probe the GenAI endpoint with a variety of converted prompts (Ex., Base64, ASCII).

5.	Memory: Utilizes DuckDB for efficient and scalable storage of conversational data, facilitating the storage and retrieval of chat histories, as well as supporting analytics and reporting.

## Code
https://github.com/Azure/PyRIT

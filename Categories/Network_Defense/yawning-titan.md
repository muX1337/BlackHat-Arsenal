# YAWNING-TITAN

## Description
YAWNING-TITAN is an abstract, graph based cyber-security simulation environment that supports the training of intelligent agents for autonomous cyber operations. YAWNING-TITAN focuses on providing a fast simulation to support the development of defensive autonomous agents who face off against probabilistic red agents. YAWNING-TITAN has been designed with the following things in mind:

• Simplicity over complexity;
• Minimal Hardware Requirements;
• Operating System agnostic;
• Support for a wide range of algorithms;
• Enhanced agent / policy evaluation support;
• Flexible environment and game rule configuration;
• Generation of evaluation episode visualisations (gifs).

YAWNING-TITAN contains a small number of specific, self-contained OpenAI Gym environments for autonomous cyber defence research, which are great for learning and debugging; it also provides a flexible, highly configurable generic environment which can be used to represent a range of scenarios of increasing complexity and scale. The generic environment only needs a network topology and a settings file to create an OpenAI Gym compliant environment which enables open research and enhanced reproducibility.

When training and evaluating an agent, YAWNING-TITAN can be run from either a command-line interface, or a graphical user interface (GUI). The GUI allows the underlying Python to be executed without need for a command line interface or knowledge of the python language. The GUI also integrates with a customised version Cytoscape JS which has been extended to work directly with YAWNING-TITAN, and allows users to directly interface with network topologies that subsequently updates a database of stored networks. Both the command-line interface and the GUI provide read-outs throughout agent training and evaluation, as well as generation of a final summary.

## Code
https://github.com/dstl/YAWNING-TITAN

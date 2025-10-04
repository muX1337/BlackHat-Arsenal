# CLExtract: An End-to-End Tool Decoding Highly Corrupted Satellite Stream from Eavesdropping

## Description
While satellite communication with ground stations can be eavesdropped on using consumer-grade products, the received signals are oftentimes highly corrupted and cannot be effectively decoded using the traditional finite-state machine (FSM) based approach.

To this end, we develop a tool named CLExtract which utilizes contrastive learning techniques to decode and recover corrupted satellite streams. Unlike the traditional FSM-based approach which relies on critical fields that become unreliable after corruption, CLExtract directly learns the features of packet headers at different layers and identifies them in a stream sequence. By filtering out these headers, CLExtract extracts the innermost payload which contains sensitive and private data. Further, CLExtract incorporates data augmentation techniques to entitle the trained contrastive learning models with robustness against unseen forms of corruption.

To evaluate CLExtract, we performed eavesdropping on the spectrum range from 11 GHZ to 12.75 GHZ in a suburban area of a metropolis with more than 10 million of population in Asia, covering radio signals from seven commercial satellites. CLExtract can successfully decode and recover 71-99% of the total 23.6GB eavesdropped data, a significant improvement over the traditional FSM-based approach implemented by GSExtract which only recovers 2%.

During the arsenal presentation, we will make CLExtract open source and demonstrate its usage to the security community using real-world satellite streams. This way, we hope to foster future research on satellite offense and defense techniques.

## Code
https://github.com/AslanDing/CLExtract

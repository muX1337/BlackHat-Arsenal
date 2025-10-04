# N3XT G3N WAF 2.0

## Description
Previously, we introduced N3XT G3N WAF (NGWAF) 1.0 at BHUSA 2022. The novel WAF 3.0 tool that seeks to relieve complex and difficult WAF detection mechanism with detection utilising a Sequential Neural Network (SNN) and traps attackers through a custom honeypotted environment. These assets are all dockerised for scalability.

However, further experiments have proven that a SNN may not be the most optimal when it comes down to contextualised defence as it processes information in a step by step and sequential manner. It gets relatively cumbersome and ineffective detecting chained or contexualised attacks. Both of which are extremely common in today's attacks.

Thus, we took another approach by swapping out our "brains". We revamped the SNN and went with a Recurrent Neural Network (RNN). The RNN is a much better choice for contextualised defense as the output of each layer is fed back as the input of the same layer. Thus, this allows the network to maintain a "memory" of the data it has processed. Our latest model is a RNN with a bi-directional LSTM module, it has an accuracy of 0.995 and a f1 score of 0.993.

We have also upgraded NGWAF's scalability in model deployment, model maintenance and the overall detection pipeline. This is all done with cloudifying the operations of the entire Machine Learning detection module. As compared to version 1.0 where users have to install and run the entire framework on their local system, NGWAF 2.0 has employed Infrastructure-as-Code (IaC) scripts, which auto-deploys the machine learning model's training & maintenance pipeline onto AWS resources (Sagemaker). The detection module has also been shifted from local deployment to AWS Sagemaker where we are able to standardise the hardware utilised for the ML model. This also allows further decoupling of the detection module from the rest of the system and allow for greater customisability.

BHUSA 2022 - Version 01: (https://www.blackhat.com/us-22/arsenal/schedule/index.html#nxt-gn-waf-ml-based-waf-with-retraining-and-detainment-through-honeypots-26609)

## Code
https://github.com/FA-PengFei/NGWAF

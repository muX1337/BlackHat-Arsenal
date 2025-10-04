# HTTP Raider - The ultimate tool for HTTP hacking

## Description
Modern websites have become a tangled mess of intricate network architectures—creating fertile ground for serious, protocol-level vulnerabilities that traditional tools often overlook.

As web applications continue to grow in complexity, we see the rise of critical vulnerabilities like smuggling, first-request routing, and cache poisoning/deception and the need for a tool that treats HTTP as what it really is: a stream based protocol.

While security professionals rely on HTTP proxies to intercept, analyze, and manipulate traffic, most of these solutions abstract away the stream-based nature of the protocol. By presenting request-response pairs as isolated transactions, they hide crucial details such as persistent connections, pipelining and geo-routing, making it difficult to fully understand how data truly flows—or to uncover advanced attack vectors.

To address these challenges, I developed HTTP Raider, an open source Burp Suite extension that helps you explore and exploit your target's underlying protocol logic with ease. It surfaces hidden details like persistent connections and pipelining, and provides absolute clarity on what's happening under the hood, empowering you to take your attacks further and exploit critical vulnerabilities that would otherwise remain undetected.

Additionally, HTTP Raider leverages error- and timing-based analyses to detect concealed proxies, caching layers, and cloud infrastructures—offering a holistic view of the network infrastructure.Through a drag-and-drop interface, users can model the flow of messages across multiple components, predicting how traffic is transformed and routed.

By removing the guesswork inherent in conventional proxies and empowering testers with a low-level view of HTTP, this tool ultimately promotes true protocol mastery—enabling researchers to discover and exploit critical vulnerabilities that would otherwise remain undetected.

## Code
https://github.com/PortSwigger/http-hacker

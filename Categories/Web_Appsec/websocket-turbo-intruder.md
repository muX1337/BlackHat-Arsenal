# WebSocket Turbo Intruder

## Description
Websites are increasingly adopting WebSockets for business critical functionality, but security tools have failed to keep up. As a result, WebSocket security testing is so painful that this ever-expanding attack surface is largely overlooked.

WebSocket Turbo Intruder is an open-source solution which makes attacks pain-free with automatic message correlation, timing and content analysis, and battle-tested matching and filtering capabilities. It also enables advanced, multi-step attack sequences thanks to an underlying Python API providing infinite customisability. It seamlessly integrates into Burp Suite, and also runs as a standalone CLI tool - ideal for launching attacks from a high-bandwidth VPS.

Under the hood, it is powered by a high-performance WebSocket engine developed from scratch for security testing, capable of sending tens of thousands of messages per second - perfect for large-scale bruteforce attacks, and triggering race conditions. The custom engine also allows the use of malformed messages, letting you exploit protocol-level implementation flaws, including a modern spin on the classic Ping-of-Death.

You can even scan WebSockets with your existing HTTP scanning tools, thanks to a convenient HTTP adapter. It is time to unlock the WebSocket goldmine.

## Code
https://github.com/PortSwigger/websocket-turbo-intruder

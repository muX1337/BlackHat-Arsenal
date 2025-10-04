# LIBIHT: A Cross-Platform Library for Accessing Intel Hardware Trace Features

## Description
Tracing stands as a vital instrument in the realm of complex software reverse engineering, but traditional tracing tools can be hindered by significant performance penalties. Instrumentation-based tracing, for instance, may incur a slowdown of up to 100x, severely limiting its practicality for in-depth analysis.

Intel CPUs have introduced a suite of hardware features, such as Last Branch Record (LBR), Branch Trace Store (BTS), and Intel Processor Trace (Intel PT), which promise to deliver detailed program tracing with minimal overhead. However, harnessing these hardware-assisted tracing capabilities is a complex task that has prevented their widespread adoption.

LIBIHT bridge this gap by offering an open-source library interface that hides all the complexity of hardware-assisted tracing and offering a user-friendly approach to interacting with advanced CPU hardware features. It collects traces by interacting with CPU hardware through its kernel components, while its user-space APIs provide a user friendly api to users.

The library assists reverse engineers by allowing them to:

- Selectively trace execution at a fine-grained level to reconstruct control flow

- Filter traces to focus on regions of interest

- Visualize traces to aid analysis

- Perform initial analysis without dealing with low-level trace formats

By bridging the kernel-user space and simplifying access to hardware traces, LIBIHT opens new capabilities for software analysis problems that are challenging with traditional debugging alone. It also lowers the bar for academic and industrial researchers to leverage the powerful tracing features in modern Intel processors.

In our talk, we will demonstrate LIBIHT's abilities through live demos. Attendees will see how to selectively trace specific regions of interest to efficiently reconstruct control flow graphs. Traces can be filtered to focus only on desired functions or call sequences. Visualization of trace data aids static analysis.

We believe LIBIHT can significantly aid reversing through its ability to efficiently recover precise control flow and execution context at scale. Its capabilities inspire further research extending hardware-assisted program analysis and instrumentation.

## Code
https://github.com/libiht/libiht

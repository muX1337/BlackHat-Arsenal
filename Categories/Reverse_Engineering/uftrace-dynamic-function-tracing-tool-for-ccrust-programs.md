# uftrace: Dynamic Function Tracing Tool for C/C++/Rust programs

## Description
uftrace is a function tracing tool that helps in the analysis of C/C++/Rust programs. It hooks into the entry and exit of each function, recording timestamps as well as the function's arguments and return values. uftrace is capable of tracing both user and kernel functions, as well as library functions and system events providing an integrated execution flow in a single timeline.

Initially, uftrace only supported function tracing with compiler support. However, it now allows users to trace function calls without recompilation by analyzing instructions in each function prologue and dynamically and selectively patching those instructions.

Users can also write and run scripts for each function entry and exit using python/luajit APIs to create custom tools for their specific purposes.

uftrace offers various filters to reduce the amount of trace data and provides visualization using Chrome trace viewer and flame graphs, allowing for a big picture view of the execution flow.

## Code
https://github.com/namhyung/uftrace

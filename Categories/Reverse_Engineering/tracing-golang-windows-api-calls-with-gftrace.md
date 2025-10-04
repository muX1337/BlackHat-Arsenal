# Tracing Golang Windows API calls with gftrace

## Description
gftrace is a Windows API tracing tool that abuses the way that the Golang runtime works to monitor all the API calls performed by Go applications. The project is a command line tool that only requires the user to specify what Windows functions to trace. Since the tool was designed to work with Go applications specifically it provides a very clean output based on the calls the main package performs and filters all the noise the Go runtime produces.

The tool is also very portable and reliable since it works with several (if not all) Go versions and only interacts with the Go runtime, without touching any Windows API call. gftrace can be very handy for fast malware triage and reverse engineering in general, specially when it comes to obfuscated, stripped and/or trojanized samples.

## Code
https://github.com/leandrofroes/gftrace

# ParseAndC 2.0 – We Don't Need No C Programs (for Parsing)

## Description
This is the 2.0 version of the ParseAndC tool that was presented in BH and DEFCON last year, with many new features added. The 1.0 version was capable of mapping any C structure(s) to any datastream, and then visually displaying the 1:1 correspondence between the variables and the data in a very colorful, intuitive display so that it was very easy to understand which field had what value.

In 2.0 version, we essentially expand the C language so that C structures alone has the same power as full-fledged C programs. We introduce Dynamic structure, which changes depending on what data it has seen till now. It supports variable-sized array, variable-sized bitfield, and addition/deletion of struct members depending on what value the previous struct members have. Suppose we are parsing the network packets, and after we decode the IP header, depending on the protocol field this tool can automatically decode the next header as either the TCP or UDP. We also add speculative execution, where user just provides the key expected values of certain fields (like magic numbers, mentioned by C initializations), and the tool automatically finds out from which offset to map so that all fields indeed have the expected value.

This tool is extremely portable – it's a single Python 1MB text file, is cross-platform (Windows/Mac/Unix), and also works in the terminal /batch mode without GUI or Internet connection. The tool is self-contained - it doesn't import anything, to the extent that it implements its own C compiler (front-end) from scratch!!

This tool is useful for both security- and non-security testing alike (reverse engineering, network traffic analyzing, packet processing etc.). It is currently being used at Intel widely. The author of this tool led many security hackathons at Intel and there this tool was found to be very useful.

## Code
https://github.com/intel/ParseAndC

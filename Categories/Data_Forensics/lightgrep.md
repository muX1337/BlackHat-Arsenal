# Lightgrep

## Description
Lightgrep is a multipattern regular expression tool for searching binary data streams, designed for digital forensics. It can search for Unicode-aware patterns in UTF-8, UTF-16, and over 100+ older encodings, including CP-1256, ISO 88599-5, and GB 18030, simultaneously, in binary and mixed-encoding data. As an automata-based engine, it provides reliable operation and copes with large pattern sets, all while adhering to well-known PCRE matching semantics.

Lightgrep has been an open source library and embedded in bulk_extractor for over a decade. It's once again under active development, with new bug fixes and performance improvements. Lightgrep is also now a useful command-line tool in its own right, with features for generating histograms, extracting hit context, and processing logs. Lightgrep is perfectly happy to search binaries, multi-GB logs, foreign language text, memory images, disk images, or unallocated clusters, for thousands of patterns.

Come to this lab to see lightgrep in action and learn to find what you're looking for, quickly and easily.

## Code
https://github.com/strozfriedberg/lightgrep

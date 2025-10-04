# unblob

## Description
One of the major challenges of embedded security analysis is the accurate extraction of arbitrary firmwares.

While binwalk has been the de-facto standard for firmware extraction since its early days, it proved to be limited in an environment where we needed to analyze heterogeneous firmwares from potentially malicious uploaders at scale.

In this talk we will introduce the audience to our specific use case, the limits of existing extraction tools, and how we overcame them by developing our very own firmware extraction framework, named unblob.

unblob is an accurate, fast, and easy-to-use extraction suite. unblob parses unknown binary blobs for more than 30 different archive, compression, and file-system formats, extracts their content recursively, and carves out unknown chunks that have not been accounted for. This turns unblob into the perfect companion for extracting, analyzing, and reverse engineering firmware images.

Similar to what HD Moore did 19 years ago when he started gathering exploit scripts in a single unifying framework with Metasploit, we'd like to provide reverse engineers with an easy to use and extensible framework to extract custom formats. Our hope is to provide a home to firmware reversers and help them not rewriting the same code every time they need to support a new vendor format.

## Code
https://github.com/onekey-sec/unblob

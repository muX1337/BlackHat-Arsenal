# cloudgrep

## Description
cloudgrep searches cloud storage.

It currently supports searching log files, optionally compressed with gzip (.gz) or zip (.zip), in AWS S3, Azure Storage or Google Cloud Storage.

Why build this?

Directly searching cloud storage, without indexing logs into a SIEM or Log Analysis tool, can be faster and cheaper.

There is no need to wait for logs to be ingested, indexed, and made available for searching.

It searches files in parallel for speed.

This may be of use when debugging applications, or investigating a security incident.

## Code
https://github.com/cado-security/cloudgrep

# DAPper - Identifying Software Packages and Uncovering Implicit Dependencies

## Description
DAPper (Dependency Analysis Project) is an open-source tool to uncover software dependencies – both explicit and implicit – by analyzing source code and system-level data. Unlike most dependency analysis tools that rely on package managers, DAPper identifies dependencies in C/C++ codebases, which typically lack a standardized package registry. It also detects subprocess execution in source code across multiple languages, revealing hidden dependencies that might otherwise go unnoticed.

These features in DAPper are powered by a set of datasets mapping file names to packages across ecosystems like Debian/Ubuntu, NuGet (Windows/.NET), PyPI, and Docker Hub. These datasets, along with tools for generating them, are released as open source, enabling broader use for software inventory analysis/system enumeration, vulnerability impact assessments, and system audits. These datasets can be particularly useful for recognizing packages on systems that lack package manager metadata, such embedded Linux systems or Windows support software used to monitor/manage/configure devices.

## Code
https://github.com/LLNL/dapper

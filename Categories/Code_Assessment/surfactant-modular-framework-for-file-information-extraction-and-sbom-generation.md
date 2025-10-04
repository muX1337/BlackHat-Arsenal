# Surfactant - Modular Framework for File Information Extraction and SBOM Generation

## Description
Surfactant is a modular framework for extracting information from filesystems, to help security analysts understand what's on a system and generating an SBOM (Software Bill of Materials). The information extracted is then used to help identify the various vendors or libraries associated with a file, and establish relationships between files. The resulting SBOM can be used for system level impact analysis (such as for IoT, Smart Grid, or ICS devices) of vulnerabilities, and the information gathered can be used to help inform what files to focus on for manual analysis by giving a better idea of how different software components relate to one another.

Several major new features will be demonstrated, including a terminal UI that makes Surfactant more accessible for users with varying levels of technical expertise, support for decompressing several common types of archives (e.g. zip and tar), and the ability to output an interactive visualization of the gathered data that shows relationships between software components. In addition, the ability to leverage the datasets released by the DAPper project  to identify what package a given file belongs to in the absence of a package manager will be demonstrated.

## Code
https://github.com/LLNL/Surfactant

# APKiD: Fast Identification of Mobile RASP SDKs

## Description
APKiD is like "PEiD" for Android applications. It gives information on how an APK was built by fingerprinting compilers, packers, obfuscators, and protectors. The main idea behind the tool is to help provide context on how the APK was potentially built or changed after it was built. This is all context useful for attributing authorship and finding patterns.

Extracting information about how the APK was made, it can provide a lot of information to assess the healthiness of an Android application (e.g. malware or pirated). The framework is the combination of a bunch of Yara rules and Python wrappers that scan files within APKs. Mainly, APKiD unpacks files and explores AndroidManifest.xml, DEX and ELF files to match rules and offers results based on them.

## Code
https://github.com/rednaga/APKiD

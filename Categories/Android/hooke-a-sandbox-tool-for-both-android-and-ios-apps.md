# Hooke: A Sandbox Tool for both Android and iOS Apps

## Description
Mainstream mobile phone systems have implemented privacy features that allow users to keep an eye on how apps access their data, such as Privacy Dashboard for Android and App Privacy Report for iOS. However, while we delved into the implementation of these systems, we found that it was not as accurate and credible as expected. We developed our offline App privacy leak detection platform - Hooke, to identify privacy-sensitive behaviors much more clearly and directly.

For data access, we identified over 300 privacy-related APIs across 8 categories for both Android and iOS, and we constructed sandbox environments and added instrumentation to collect runtime information like parameters, stack traces and app status. For network behavior, we found a general solution to bypass ssl pinning, and tried to decrypt network traffic to prevent sensitive data escape. To facilitate locating privacy issues, our sandbox also recorded App runtime screens and timestamps during the test phase, which are associated directly with dynamic behaviors.

Our tool, Hooke, shows App behaviors in the aspect of privacy data access, network traffic and screen recordings, and we also implemented an intelligent rule engine to analyze this data. Finally, these three categories data are associated and presented in the form of a timeline, aiming to directly and easily locate an App's behavior throughout the app's lifecycle by dragging the timeline. With the help of Hooke, we found dozens of privacy leak issues hidden in malicious Apps and third-party SDKs.﻿

## Code
https://github.com/bytedance

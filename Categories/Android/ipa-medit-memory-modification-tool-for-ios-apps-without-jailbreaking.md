# Ipa-medit: Memory modification tool for iOS apps without Jailbreaking

## Description
Ipa-medit is a memory search and patch tool for resigned ipa without jailbreaking. It supports iOS apps running on iPhone and Apple Silicon Mac. It was created for mobile game security testing. Many mobile games have jailbreak detection, but ipa-medit does not require jailbreaking, so memory modification can be done without bypassing the jailbreak detection.

Memory modification is the easiest way to cheat in games, it is one of the items to be checked in the security test. There are also cheat tools that can be used casually like GameGem and iGameGuardian. However, there were no tools available for un-jailbroken device and CUI, Apple Silicon Mac. So I made it as a security testing tool.

I presented a memory modification tool ipa-medit which I presented at Black Hat USA 2021 Arsenal. At that time, it could only target iOS apps running on iPhone, but now it supports iOS apps running on the Apple Silicon Mac. The Apple Silicon Mac was recently released and allows you to run iOS apps on macOS. For memory modification, I'll explain how the implementation and mechanisms are different for iOS apps running on iPhone or Apple Silicon Mac.

## Code
https://github.com/aktsk/ipa-medit

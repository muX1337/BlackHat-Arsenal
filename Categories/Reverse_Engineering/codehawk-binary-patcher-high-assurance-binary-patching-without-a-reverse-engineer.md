# CodeHawk Binary Patcher: High Assurance Binary Patching Without a Reverse Engineer

## Description
The CodeHawk Binary Patcher (CBP) project is a partnership between MIT

CSAIL and Aarno Labs with the goal of democratizing binary

patching. The project focuses on 1) drastically reducing the time to

understand and patch stripped binaries, and 2) providing provable

assurance results that demonstrate whether a patch has been correctly

applied to fix a vulnerability or bug while maintaining correct

behaviors.

The process begins with an abstract interpretation based analysis on

the binary that extracts facts about the binary at each

instruction. The analysis is scalable, having been demonstrated to

successfully analyze huge binaries (e.g., the Linux Kernel). CBP

produces an editable lifting of the binary represented in the C

programming language. An operator without reverse engineering

experience will then directly edit the C code representation, and CBP

can enact those changes on the binary using the provenance information

produced along with the lifting, without recompiling the binary.

After a patch has been produced, CBP runs a suite of checkable

relational analyses that provide information about how the patched

binary differs from the original, enabling an operator to quickly

decide if the patch is correct. Furthermore, CBP provides checkable

proofs as evidence that its transformations are correct, and for

certain important types of memory vulnerabilities, can prove that a

patch fixes the vulnerability. This entire workflow is available as in

a GUI plugin to the Binary Ninja platform.

CBP is built on top of CodeHawk's open-source binary analysis,

developed over the past 10 years through DARPA and IARPA funding

(STONESOUP, MUSE, HACCS, STAC, and AMP).

CBP has been independently demonstrated in the DARPA's Assured

Micro-Patching (AMP) evaluations to drastically reduce the time, cost,

and risk of binary patching, providing intuitive and provable

assurance results of a binary patch.

## Code
https://github.com/static-analysis-engineering/CodeHawk-Binary

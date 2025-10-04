# Introducing varc: Volatile Artifact Collector

## Description
open source volatile artifact collection tool.

Driven by a philosophy of simplicity and reliability, the tool was
developed to aid investigation of security incidents, and is available
to the community under a friendly licence. Varc achieves this by
collecting a snapshot of volatile data from a system and outputting it
as JSON - so that it can easily be ingested by another parser or read
by a human investigator.

Varc’s design philosophy has an emphasis on portability, meaning that
it can run across operating systems, in cloud and on-premise
environments – and also supports serverless artifact collection.

And if there is a demo talk requirement:

In this talk, Matt Muir, Threat Intelligence Researcher, Cado Security
and Chris Doman, CTO Cado Security will discuss the motivation for
developing varc. They’ll also cover the technical challenges inherent
to volatile artifact collection in serverless environments and across
operating systems. Finally, they’ll give a live demonstration of varc
and show the audience how it can be used to aid incident response.

Description
The talk will be divided into the following 4 sections:
1) Background and Motivation
2) Technical Challenges
3) varc Demonstration
4) Conclusion

Background and Motivation
Matt and Chris will begin the talk with some discussion of what
exactly varc is and an overview of its features. They’ll then move
on to discuss the reason for Cado Security’s development of this tool
and what problems varc addresses, when compared with other volatile
collection tools. Some background to varc’s design philosophy will
also be provided.

Technical Challenges
In this section, Matt and Chris will discuss the various technical
challenges that working with volatile data presents. This will include
an overview of which artifacts were deemed important to an incident
responder and how these can be accessed via Python code on the various
operating systems varc supports. There will also be some discussion on
how varc operates in serverless environments and what this means for
investigators working in this area.

varc Demonstration
This section will include a demonstration of varc on a system where
some malicious activity has occurred. Matt and Chris will highlight
artifacts of interest and demonstrate varc’s extraction and
presentation of these to the audience.

Conclusion
The talk will conclude with discussion about how varc is integrated
into Cado and how this benefits users of the platform. Matt and Chris
will also discuss the potential for further work in this area and
provide the audience with details of how they can get involved.
Finally, a Q&A session will give the audience an opportunity to have
any questions about varc answered.

## Code
https://github.com/cado-security/varc

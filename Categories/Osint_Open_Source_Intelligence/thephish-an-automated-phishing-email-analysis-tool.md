# ThePhish: an automated phishing email analysis tool

## Description
ThePhish is an automated phishing email analysis tool based on TheHive, Cortex and MISP. It is a web application written in Python 3 and based on Flask that automates the entire analysis process starting from the extraction of the observables from the header and the body of an email to the elaboration of a verdict which is final in most cases. In addition, it allows the analyst to intervene in the analysis process and obtain further details on the email being analyzed if necessary. In order to interact with TheHive and Cortex, it uses TheHive4py and Cortex4py, which are the Python API clients that allow using the REST APIs made available by TheHive and Cortex respectively.

## Code
https://github.com/emalderson/ThePhish

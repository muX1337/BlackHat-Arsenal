# Akto - Open Source API Security Tool

## Description
We released Open source Akto in Feb '23 & we have 310 stars on Github. This tool is mainly focuses on solving the problems below:
1. Tough api inventory for both testers, compliance and developers
2. Testing with complex chained apis - Multi step authentication, refresh/access token etc.
3. Automated testing of APIs - Both OWASP Top 10 and some business logic tests

Our tool Akto focuses on solving the above problems by providing:
1. Provide automated API inventory -
a)Automated - Akto can populate inventory automatically from traffic sources like Burp Proxy, Postman or even Chrome HAR files.
b) All formats - Akto also covers different formats of APIs such as JSON, GraphQL, gRPC, JSONP, forms.
2. Inspects traffic & provides alerts on suspicious apis -
a) Sensitive data - Akto comes with an in-built library for sensitive data patterns. Akto can tell which APIs are sharing sensitive data such as SSN, email, Phone number etc. Users can add their own patterns too.
b) Alerts - Users can set up daily alerts using Slack and Webhooks to get alerts about new sensitive data/APIs found
3. Automated API testing which covers OWASP Top 10 & some business logic testing
a) OWASP Coverage - Akto has 130+ tests to cover for OWASP Top 10
b) Business logic tests - Akto also supports business logic tests such as BOLA, Broken Function Level Authorization, Broken Authentication etc.
c) Add your own - Users can also add their own tests.

This tool will be very interesting for:
a) Bugbounty Hunters - has a blackbox feature where complex apis can be uploaded from Burp history & can be useful for chained requests.
b) Pentesters & testing teams in appsec - getting accurate api collection is complex & time consuming. Provides a one stop solution for getting the inventory. Tests like BOLA and BFLA will be especially interesting for them.
c) Blue teamers/infra security - Getting an automated API inventory and getting alerts for any new sensitive APIs. They can also get a view of all sensitive PII data being shared across all their services and across all their APIs. They can check unauthenticated APIs, download the swagger file and use it in other security apps too.

## Code
https://github.com/akto-api-security/akto

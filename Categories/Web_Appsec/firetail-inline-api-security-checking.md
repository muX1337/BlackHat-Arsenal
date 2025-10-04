# FireTail - inline API security checking

## Description
FireTail sits on top of popular open source frameworks for building web services and APIs, like OpenAPI/Swagger, Express and Rails, and then provides in-line security processing of the API calls. FireTail checks for (in sequential order):
1. API call is hitting valid route using a valid method. This allows for a zero-trust, declarative API structure, with proper error handling at the HTTP layer.
2. Inspection of authentication token. Does the API expect a JWT, application-issued API key or other? FireTail will check whether a valid token of the correct type is present.
3. Payload inspection. FireTail will look for and fail invalid queries.

https://firetail.io/

## Code
https://github.com/firetail-io

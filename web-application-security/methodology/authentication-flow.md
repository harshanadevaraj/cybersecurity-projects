# Authentication Traffic Analysis

## Objective
Inspect the application's login request and response using Burp Suite.

## Observations
- HTTP method: POST
- Endpoint: /rest/user/login
- Response status: 200 OK
- Authentication mechanism: Token-based authentication
- Token/cookie observed: Yes

## Security Notes
- Credentials were transmitted over local HTTP.
- Authentication token handling was observed.
- No vulnerability is claimed from observation alone.

## Evidence
- 01-initial-http-traffic.png
- 02-login-request-response.png

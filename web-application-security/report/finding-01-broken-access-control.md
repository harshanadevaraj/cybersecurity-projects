# Finding 01: Broken Access Control in Basket API

## Summary
An authenticated user can retrieve another user's basket
by requesting a basket ID that does not belong to them.

## Vulnerability classification
- Category: Broken Access Control
- Type: IDOR / Broken Object-Level Authorization (BOLA)
- OWASP: Broken Access Control
- Endpoint: GET /rest/basket/{id}

## Test environment
- Application: OWASP Juice Shop
- Deployment: Local Docker container
- Testing tool: Burp Suite Community Edition
- Testing method: Manual request manipulation using Repeater

## Reproduction
1. Created two separate test accounts.
2. Authenticated as the first account (User ID 26).
3. Identified its basket ID (6).
4. Authenticated as the second account (User ID 27).
5. Sent GET /rest/basket/6 using the second account's
   authentication token.
6. Removed conditional cache headers to obtain a fresh response.

## Observed result
HTTP response: 200 OK

The response contained:
- Basket ID: 6
- Basket owner UserId: 26
- Products: Empty array

The authenticated user was User ID 27.

## Expected result
The server should deny access to a basket belonging to
another user, returning an appropriate authorization error.

## Security impact
An authenticated user may access another user's basket
metadata by manipulating the basket identifier.

The tested basket contained no products. Exposure of
additional basket information or product data has not
been established.

## Recommended remediation
- Enforce server-side basket ownership checks.
- Derive the authenticated user identity from the validated session.
- Verify that the requested basket belongs to that user.
- Deny unauthorized access rather than relying on client-side checks.
- Add automated authorization tests for cross-user object access.

## Limitations
Testing was conducted exclusively against a local,
intentionally vulnerable OWASP Juice Shop instance.

No production systems were tested.

## Comparative authorization test

Two test accounts were used.

| Authenticated user | Basket ID | Basket owner | Response |
|---|---:|---:|---|
| User 27 | 7 | 27 | 200 OK |
| User 27 | 6 | 26 | 200 OK |

The second account could retrieve both its own basket
and the first account's basket.

This confirms missing server-side ownership enforcement
for the tested basket retrieval endpoint.![alt text](04-xss-dom-inspection.png) ![alt text](03-xss-alert.png)
# Finding 02: Cross-Site Scripting in Search Functionality

## Summary
User-controlled search input was able to trigger JavaScript
execution in the OWASP Juice Shop browser application.

## Vulnerability classification
- Category: Cross-Site Scripting (XSS)
- Classification: XSS (exact subtype not yet established)
- OWASP category: Injection
- Application: OWASP Juice Shop
- Testing tool: Burp Suite Community Edition

## Test environment
- Application deployed locally using Docker
- Target: http://127.0.0.1:3000
- Browser: Burp Suite built-in browser

## Reproduction
1. Opened the Juice Shop search functionality.
2. Entered an HTML formatting test string.
3. Inspected the rendered DOM and observed an actual
   HTML bold element.
4. Entered the following JavaScript execution test:

   <img src=x onerror=alert('XSS-test')>

5. Observed a browser alert displaying XSS-test.

## Observed result
JavaScript execution was observed through the search input.

## Expected result
User-controlled search input should be handled safely.
Untrusted content must not execute as JavaScript.

## Security impact
If exploitable by an attacker against another user's browser,
this class of vulnerability may enable actions in the context
of the affected application, depending on session protections
and browser controls.

No account compromise or data theft was tested.

## Recommended remediation
- Avoid unsafe DOM insertion of user-controlled input.
- Use safe text-rendering APIs and framework escaping.
- Sanitize HTML if HTML rendering is genuinely required.
- Apply an appropriate Content Security Policy as defense in depth.
- Add regression tests for malicious search input.

## Evidence
- 03-xss-alert.png
- 04-xss-dom-inspection.png

## Limitations
Testing was conducted only against a local, intentionally
vulnerable OWASP Juice Shop instance.

The precise DOM execution context and exploitability against
other users require further validation.

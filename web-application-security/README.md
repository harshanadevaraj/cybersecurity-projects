# Web Application Security Assessment Using Burp Suite

## Overview
A hands-on web application security assessment conducted
against OWASP Juice Shop, an intentionally vulnerable
web application deployed locally using Docker.

## Objectives
- Inspect HTTP requests and responses using Burp Suite.
- Examine authentication and session handling.
- Test object-level authorization.
- Assess user-controlled search input for XSS.
- Document findings, evidence, impact, and remediation.

## Tools
- Burp Suite Community Edition
- OWASP Juice Shop
- Docker
- Browser Developer Tools

## Findings

### 1. Broken Object-Level Authorization (BOLA)
The basket API returned basket metadata belonging to another
user when accessed using a different authenticated account.

See: report/finding-01-broken-access-control.md

### 2. Cross-Site Scripting (XSS)
A JavaScript alert was triggered through user-controlled
search input in the local application.

See: report/finding-02-xss.md

## Methodology
Manual testing using Burp Proxy, HTTP history, and Repeater,
with separate test accounts and controlled payloads.

## Evidence
Screenshots are stored in the evidence directory.

## Limitations
Testing was performed exclusively against a local
OWASP Juice Shop instance. Findings describe the tested
application and do not imply vulnerabilities in other systems.

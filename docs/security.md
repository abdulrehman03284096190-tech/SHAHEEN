# Security

Shaheen treats captured traffic as untrusted input and avoids executing arbitrary code from rules or packet content.

## Safeguards

- Parameterized SQL usage.
- Restricted filter parsing.
- AI requests remain opt-in and can be mocked.
- Sensitive data should not be stored in source control or logs.

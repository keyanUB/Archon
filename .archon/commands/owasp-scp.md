# OWASP Secure Coding Practices — Quick Reference

## Input Validation
- Validate all input server-side; never trust client-supplied data
- Use allowlists (expected values) over denylists
- Validate type, length, range, and format; reject — do not sanitize — invalid input
- Validate all data sources: URL params, headers, cookies, JSON fields, file uploads
- Reject requests with unexpected extra fields (mass assignment protection)

## Output Encoding
- Encode output for the target context: HTML entities, JSON escaping, URL encoding, shell quoting
- Never concatenate user-controlled data into HTML, SQL, shell commands, or XML
- Use context-aware encoding libraries; do not hand-roll encoding

## Authentication & Password Management
- Use vetted authentication libraries; do not implement custom auth
- Hash passwords with bcrypt, argon2id, or scrypt — never MD5, SHA-1, or unsalted hashes
- Enforce minimum password complexity; store only the hash, never the plaintext
- Implement account lockout or progressive delay after repeated failures
- Use secure, random tokens for password reset; expire them after single use

## Session Management
- Generate session IDs with a CSPRNG; minimum 128 bits of entropy
- Rotate session ID on privilege change (login, role escalation)
- Set `HttpOnly`, `Secure`, and `SameSite=Strict` on session cookies
- Enforce absolute and idle session timeouts
- Invalidate the session server-side on logout

## Access Control
- Deny by default; explicitly grant the minimum required access
- Enforce access checks server-side on every request — never trust client-side gates
- Use role/attribute-based access control; avoid direct object references from user input
- Log and alert on repeated authorization failures

## Cryptographic Practices
- Use established, peer-reviewed libraries (libsodium, OS crypto APIs, TLS stacks)
- Never implement custom cryptographic algorithms
- Use AES-256-GCM for symmetric encryption; RSA-2048+ or ECDSA P-256+ for asymmetric
- Generate keys and IVs with a CSPRNG; never reuse IVs with the same key
- Rotate and revoke cryptographic keys; store them outside the codebase

## Error Handling & Logging
- Never expose stack traces, internal paths, query strings, or secret values in error responses
- Return generic error messages to clients; log full detail server-side only
- Fail securely — deny access on error, never grant it
- Log authentication events, access denials, and input validation failures
- Never log passwords, tokens, session IDs, or PII

## Data Protection
- Use parameterized queries or prepared statements for all database operations — no string concatenation
- Encrypt sensitive data at rest (AES-256); use TLS 1.2+ for data in transit
- Do not store sensitive data beyond its required retention period
- Mask or truncate sensitive values in logs and API responses (e.g. show last 4 digits only)
- Apply least privilege to database credentials; separate read and write accounts where feasible

## Communication Security
- Enforce TLS 1.2+ on all connections; disable SSLv3, TLS 1.0, TLS 1.1
- Validate TLS certificates; reject self-signed certs in production
- Use HSTS (`Strict-Transport-Security`) with a long max-age
- Pin certificates or public keys for high-value connections

## Database Security
- Apply least privilege: app accounts should not have DDL or admin rights
- Use parameterized queries exclusively — never build queries via string interpolation
- Disable stored procedures and features not in use
- Validate and escape all data before persistence, even from internal sources

## File Management
- Validate file type by inspecting content (magic bytes), not extension alone
- Reject path traversal sequences (`../`, `..%2F`, null bytes) in file paths
- Store uploaded files outside the web root; serve via a controlled endpoint
- Limit file size and allowed MIME types; scan uploads for malicious content
- Never pass user-supplied file names to OS commands or `include`/`require` calls

## General Coding Practices
- Keep dependencies minimal and up to date; review changelogs for security advisories
- Remove dead code, debug endpoints, and development backdoors before shipping
- Avoid deprecated or known-insecure APIs (e.g. `eval`, `exec` with user input, `pickle` on untrusted data)
- Use memory-safe languages or memory-safe APIs; bounds-check all buffer operations
- Document security-relevant decisions and non-obvious invariants inline

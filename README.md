 OWASP Top 10 - Fixes and Explanations

This repository contains a single Python Flask demo (`owaspfixes.py`) that demonstrates secure fixes for several OWASP Top 10 vulnerabilities presented in the assignment prompt. The goal is educational: show the vulnerability, the reasoning, and a secure implementation pattern.

## What you’ll find

* `owaspfixes.py` — A runnable Flask application with example endpoints that show how to fix common mistakes:

  1. Broken Access Control (`/profile/<id>`, `/account/<id>`) — authorization enforced (owner or admin only).
  2. Cryptographic Failures (`/register`, `/login`) — passwords hashed with bcrypt, not MD5/SHA1.
  3. SQL Injection (`/find-user`) — parameterized queries used with sqlite3.
  4. NoSQL injection prevention (`/mongo-user`) — strict input validation and avoidance of raw JSON query construction.
  5. Insecure Design - Password reset flow (`/request-reset`, `/reset-password`) — token-based reset with constant time compare.
  6. Software & Data Integrity (`/fetch-lib`) — verify SHA256 integrity for remote resources and whitelist sources.
  7. SSRF (`/fetch-url`) — whitelist hosts and validate URLs before fetching.
  8. Identification & Authentication (`/login`, `/change-password`) — use bcrypt for password checks and avoid plaintext comparisons.

> Note: For brevity, some production best practices are simplified (e.g., token expiry storage, secure session handling, secret management). Do not use this demo as-is in production.

---

## For each vulnerability (summary and fixes)

### Broken Access Control (items 1 & 2)

**Problem:** Endpoints returned user data based solely on `userId` path parameters with no authorization checks. Attackers can enumerate or access other users' data.

**Fix implemented:** enforce authentication and authorization. Only the resource owner or users with the `admin` role can access another user's profile. We check `X-User-Id` header (demo only) and compare to the requested id.

**Why this helps:** Ensures least privilege and prevents horizontal privilege escalation. In production, replace header-based auth with secure sessions or signed tokens (e.g., JWTs) and role checks.

### Cryptographic Failures (items 3 & 4)

**Problem:** MD5 or SHA1 were used to hash passwords — both are broken and too fast for password hashing.

**Fix implemented:** Use `bcrypt` for password hashing and verification. Also enforce a minimum password length policy in the demo.

**Why this helps:** Bcrypt is an adaptive, slow hashing algorithm with a built-in salt. It significantly increases the cost for offline cracking attacks.

### Injection (items 5 & 6)

**Problem (SQLi):** Building SQL by concatenating strings allows malicious SQL to be injected.

**Fix implemented (SQL):** Use parameterized SQL queries via `sqlite3` placeholders.

**Problem (NoSQL injection):** Trusting unvalidated query parameters can allow attacker-controlled query operators.

**Fix implemented (NoSQL-like):** Strict input validation (regex) and avoiding building raw query objects from user input. When using real NoSQL drivers, avoid passing unsanitized user-supplied JSON as queries.

**Why this helps:** Parameterized queries avoid altering SQL structure. Input validation prevents attacker-supplied operators or types from being misinterpreted by the database.

### Insecure Design (item 7) - Password Reset

**Problem:** Reset endpoint simply accepted an email and new password — no proof the requester controlled the email address.

**Fix implemented:** Implemented token-based flow: `request-reset` generates a secure token and (simulated) emails a link. `reset-password` validates the token using constant-time compare and then updates the hash.

**Why this helps:** Ensures attacker cannot reset arbitrary accounts without access to the user's email. Token is random and unpredictable.

### Software & Data Integrity Failures (item 8)

**Problem:** Blindly loading third-party scripts or resources from CDNs without verifying integrity can lead to supply-chain attacks.

**Fix implemented:** Demonstrated a `fetch-lib` endpoint that only allows whitelisted URLs and verifies content SHA256 matches expected value before using it.

**Why this helps:** Verifying hashes prevents silent compromise if CDN content is altered. In browsers, prefer Subresource Integrity (SRI) and pin trusted versions.

### Server-Side Request Forgery (item 9)

**Problem:** `requests.get(url)` without validation allows SSRF — attacker can force server to access internal services.

**Fix implemented:** `is_safe_url` ensures URL scheme is http/https and hostname is in an allowlist. Requests also use short timeouts.

**Why this helps:** Limits external requests to known good hosts and avoids contacting internal metadata endpoints or private IPs.

### Identification & Authentication Failures (item 10)

**Problem:** Comparing plaintext input password to stored password value directly allows insecure password storage and timing issues.

**Fix implemented:** Use `bcrypt.checkpw` to compare hashed passwords. The login endpoint demonstrates secure authentication.

**Why this helps:** Proper hash verification avoids storing plaintext and uses a constant-time compare internally.

---

## How to run the demo

1. Create a Python virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate
pip install flask bcrypt requests
```

2. Run the app:

```bash
python owaspfixes.py
```

3. Use `curl` or Postman to interact with endpoints. Example: register and login flow, or try `GET /profile/1` with header `X-User-Id: 1`.

---

## References

* OWASP Top 10 (latest): [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
* SQL Injection prevention: [https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
* Password storage cheat sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* SSRF prevention: [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* Access Control: [https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html)

---

## Notes and next steps

This demo is for learning and should be extended for production use:

* Persist reset token expiry and use hashed tokens in storage.
* Replace header-based auth with JWTs or secure server sessions.
* Harden allowed host checks (including IP range checks) for SSRF protection.
* Use CSP and SRI for browser-loaded resources, and pin package versions for server dependencies.

If you'd like, I can:

* Create a GitHub repo and push these files.
* Add unit tests for endpoints.
* Produce the optional 1-minute screen recording script and steps.


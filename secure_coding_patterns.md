# Secure Coding Patterns - JavaScript/Node.js

**SSE - Secure Software Engineering | MESW 25/26 | FEUP**

A quick-reference guide of anti-patterns and fixes organized by OWASP Top 10 (2021) category. All examples use JavaScript/Node.js/Express. Each entry includes the CWE identifier, the OWASP ASVS 5.0 section, and ready-to-use code.

> **How to use this document:** Each pattern shows a ❌ anti-pattern (what NOT to do) and a ✅ fix (what to do instead). Use it during code reviews, labs, and your project work.

**References:**
- OWASP Cheat Sheet Series - ASVS Index: https://cheatsheetseries.owasp.org/IndexASVS.html
- OWASP Cheat Sheet Series - Top 10 Index: https://cheatsheetseries.owasp.org/IndexTopTen.html
- OWASP Node.js Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
- Checkmarx JS-SCP (JavaScript Secure Coding Practices): https://github.com/Checkmarx/JS-SCP
- Express Security Best Practices: https://expressjs.com/en/advanced/best-practice-security.html

---

## A01 - Broken Access Control

### 1.1 Missing Authorization (CWE-862) - ASVS V8.3

```javascript
// ❌ Any logged-in user can delete any account
app.post("/admin/deleteUser", requireAuth, async (req, res) => {
  await db.query("DELETE FROM users WHERE id = $1", [req.body.userId]);
  res.json({ ok: true });
});
```

```javascript
// ✅ Enforce role AND validate target resource
app.post("/admin/deleteUser", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const targetId = Number(req.body.userId);
  if (!Number.isInteger(targetId)) {
    return res.status(400).json({ error: "Bad userId" });
  }
  await db.query("DELETE FROM users WHERE id = $1", [targetId]);
  res.json({ ok: true });
});
```

**Rule:** Authentication proves who you are. Authorization controls what you can do. Every privileged action needs explicit authorization logic.

---

### 1.2 Insecure Direct Object Reference / IDOR (CWE-639) - ASVS V8.3

```javascript
// ❌ User can access any invoice by changing the ID
app.get("/invoices/:id", requireAuth, async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  res.json(invoice);
});
```

```javascript
// ✅ Query scoped to the authenticated user
app.get("/invoices/:id", requireAuth, async (req, res) => {
  const invoice = await Invoice.findOne({
    _id: req.params.id,
    userId: req.user.id   // must belong to this user
  });
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }
  res.json(invoice);
});
```

**Rule:** Always scope data queries to the authenticated user. Return 404 (not 403) for unauthorized resources to prevent enumeration.

---

### 1.3 Missing Function-Level Access Control (CWE-285) - ASVS V8.3

```javascript
// ❌ Admin endpoint has no role check - hidden URL ≠ security
app.get("/api/admin/users", requireAuth, async (req, res) => {
  const users = await db.query("SELECT * FROM users");
  res.json(users.rows);
});
```

```javascript
// ✅ Role-based middleware enforces access
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

app.get("/api/admin/users", requireAuth, requireRole("admin"), async (req, res) => {
  const users = await db.query("SELECT id, email, role FROM users"); // no passwords
  res.json(users.rows);
});
```

**Rule:** Never rely on URL obscurity for security. Enforce authorization via middleware that checks roles on every request.

---

## A02 - Cryptographic Failures

### 2.1 Weak Password Hashing (CWE-916) - ASVS V11.4

```javascript
// ❌ MD5 with no salt - brute-forceable in seconds
const crypto = require("crypto");
const hash = crypto.createHash("md5").update(password).digest("hex");
```

```javascript
// ✅ bcrypt with automatic salt and configurable work factor
const bcrypt = require("bcrypt");
const SALT_ROUNDS = 12;

// Hash
const hashed = await bcrypt.hash(password, SALT_ROUNDS);

// Verify (timing-safe comparison built in)
const valid = await bcrypt.compare(password, hashed);
```

**Rule:** Never use MD5, SHA-1, or SHA-256 alone for passwords. Use adaptive hashing algorithms: bcrypt, scrypt, or Argon2.

---

### 2.2 Hardcoded Secrets (CWE-798) - ASVS V13.3

```javascript
// ❌ API key committed to source code
const API_KEY = "sk-live-4eC39HqLyjWDarjtT1zdp7dc";
const stripe = require("stripe")(API_KEY);
```

```javascript
// ✅ Load from environment / secrets manager
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
// Production: use HashiCorp Vault, AWS Secrets Manager,
// Azure Key Vault, or GCP Secret Manager
```

**Rule:** If it's in your code, it's in your repository. If it's in your repository, assume it's public. Use environment variables for dev, secrets managers for production.

---

### 2.3 Insecure Randomness (CWE-338) - ASVS V11.5

```javascript
// ❌ Math.random() is not cryptographically secure
const token = Math.random().toString(36).substring(2);
```

```javascript
// ✅ Use crypto.randomBytes for security-sensitive tokens
const crypto = require("crypto");
const token = crypto.randomBytes(32).toString("hex");
```

**Rule:** `Math.random()` is predictable. Use `crypto.randomBytes()` or `crypto.randomUUID()` for tokens, session IDs, and nonces.

---

## A03 - Injection

### 3.1 SQL Injection (CWE-89) - ASVS V1.2.4

```javascript
// ❌ User-controlled 'name' is concatenated into SQL
app.get("/users", async (req, res) => {
  const name = req.query.name;
  const sql = `SELECT * FROM users WHERE name = '${name}'`;
  const rows = await db.query(sql);
  res.json(rows);
});
// Attacker sends: ?name=' OR 1=1 --
```

```javascript
// ✅ Always bind parameters
app.get("/users", async (req, res) => {
  const name = req.query.name;
  const rows = await db.query(
    "SELECT * FROM users WHERE name = $1",
    [name]
  );
  res.json(rows);
});
```

**Rule:** User input should never shape your SQL logic, only your parameters. Use parameterized queries or ORMs.

---

### 3.2 NoSQL Injection (CWE-943) - ASVS V1.2.4

```javascript
// ❌ MongoDB query operator injection
app.post("/login", async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password    // attacker sends { "$ne": "" }
  });
  if (user) res.json({ success: true });
});
```

```javascript
// ✅ Sanitize input and enforce types
const mongoSanitize = require("express-mongo-sanitize");
const bcrypt = require("bcrypt");
app.use(mongoSanitize());

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid input" });
  }
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  res.json({ success: true });
});
```

**Rule:** MongoDB operators like `$ne`, `$gt`, `$regex` in user input bypass authentication. Strip `$`-prefixed keys or enforce strict type checking.

---

### 3.3 Cross-Site Scripting / XSS (CWE-79) - ASVS V1.2.1

```javascript
// ❌ Unescaped 'q' is reflected into HTML
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.type("html").send(`<h1>Results for: ${q}</h1>`);
});
// payload: ?q=<script>alert(1)</script>
```

```javascript
// ✅ Context-appropriate escaping
import he from "he";

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  const safeQ = he.encode(q);
  res.type("html").send(`<h1>Results for: ${safeQ}</h1>`);
});
```

**Rule:** Encode on output for the right context (HTML, attribute, JS, URL). Input validation reduces risk; output encoding prevents execution.

---

### 3.4 Command Injection (CWE-78) - ASVS V1.2.5

```javascript
// ❌ User input passed directly to shell command
const { exec } = require("child_process");
app.get("/dns", (req, res) => {
  exec(`nslookup ${req.query.host}`, (err, stdout) => {
    res.send(stdout);
  });
});
// Attacker sends: ?host=example.com; cat /etc/passwd
```

```javascript
// ✅ Use execFile (no shell) + input validation
const { execFile } = require("child_process");

app.get("/dns", (req, res) => {
  const host = req.query.host;
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).json({ error: "Invalid hostname" });
  }
  execFile("nslookup", [host], (err, stdout) => {
    res.send(stdout);
  });
});
```

**Rule:** Never pass user input to `exec()`. Use `execFile()` (no shell interpolation) and validate input against an allowlist pattern.

---

### 3.5 Path Traversal (CWE-22) - ASVS V1.2

```javascript
// ❌ User controls file path directly
const fs = require("fs");
app.get("/files", (req, res) => {
  const filePath = req.query.name;
  res.sendFile(filePath);
});
// Attacker sends: ?name=../../etc/passwd
```

```javascript
// ✅ Canonicalize, then validate against allowed base directory
const path = require("path");

app.get("/files", (req, res) => {
  const BASE_DIR = path.resolve("/app/uploads");
  const requested = path.resolve(BASE_DIR, req.query.name);

  if (!requested.startsWith(BASE_DIR)) {
    return res.status(403).json({ error: "Access denied" });
  }
  res.sendFile(requested);
});
```

**Rule:** Canonicalize first, then validate. Resolve the full path and verify it stays within the allowed base directory.

---

## A04 - Insecure Design

> A04 addresses architectural/design flaws, not implementation bugs. It cannot be fixed by better coding alone; it requires secure design practices (threat modeling, ARA, secure design patterns). See the Design Phase lecture for full coverage.

**Example:** An application that allows unlimited password attempts without rate limiting has an insecure design. No amount of input validation fixes the missing rate-limiting requirement.

```javascript
// ❌ No rate limiting on login - brute-force possible
app.post("/login", async (req, res) => {
  // ... authentication logic, no attempt tracking
});
```

```javascript
// ✅ Rate limiting as a design control
const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 attempts per window
  message: { error: "Too many login attempts. Try again later." }
});

app.post("/login", loginLimiter, async (req, res) => {
  // ... authentication logic
});
```

**Rule:** Security controls like rate limiting, account lockout, and CAPTCHA are design decisions that must be planned before implementation.

---

## A05 - Security Misconfiguration

### 5.1 Wide-Open CORS + Debug Mode (CWE-16) - ASVS V13

```javascript
// ❌ Wide-open CORS + debug in prod
app.use(require("cors")());
const DEBUG = true;
```

```javascript
// ✅ Secure defaults & environment-based config
import cors from "cors";

const DEBUG = process.env.NODE_ENV !== "production";
const ALLOWLIST = ["https://app.example.com"];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWLIST.includes(origin)) cb(null, true);
    else cb(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST"],
  credentials: true
}));
```

**Rule:** Default to secure settings. Anything risky should require explicit opt-in and review.

---

### 5.2 Missing Security Headers (CWE-16) - ASVS V13

```javascript
// ❌ No security headers - Express default only sets X-Powered-By
const app = express();
// Missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options...
```

```javascript
// ✅ Helmet sets 13 security headers with one line
import helmet from "helmet";
const app = express();
app.use(helmet());
```

**Rule:** Use Helmet.js. One line of code, 13 security headers. See https://helmetjs.github.io/

---

### 5.3 Insecure Cookie Configuration (CWE-614) - ASVS V7.2

```javascript
// ❌ Session cookie with unsafe defaults
app.use(session({
  secret: "keyboard cat",
  cookie: {}
}));
```

```javascript
// ✅ Hardened session cookie
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,        // HTTPS only
    httpOnly: true,       // no JavaScript access
    sameSite: "strict",   // CSRF protection
    maxAge: 3600000       // 1 hour expiry
  }
}));
```

**Rule:** Cookies carrying session tokens must be secure, httpOnly, and sameSite. Never hardcode session secrets.

---

### 5.4 Verbose Errors in Production (CWE-209) - ASVS V16.5

```javascript
// ❌ Stack traces returned to users
app.use((err, req, res, next) => {
  res.status(500).json({
    message: err.message,
    stack: err.stack
  });
});
```

```javascript
// ✅ Environment-aware error handling
app.use((err, req, res, next) => {
  console.error("Unhandled error", { msg: err.message, url: req.originalUrl });
  res.status(500).json({
    error: process.env.NODE_ENV === "production"
      ? "Internal server error"
      : err.message
  });
});
```

**Rule:** Generic errors to users. Detailed errors to logs only.

---

## A06 - Vulnerable and Outdated Components

> A06 is primarily about process, not code patterns. Use Software Composition Analysis (SCA) tools to detect vulnerable dependencies.

```bash
# Check for known vulnerabilities in your dependencies
npm audit

# Fix automatically where possible
npm audit fix

# Use Snyk for deeper analysis
npx snyk test
```

**Tools:** npm audit, Snyk, Dependabot, Socket.dev, Trivy

**Rule:** Know what you depend on. Keep it updated. Automate vulnerability scanning in CI/CD.

---

## A07 - Identification and Authentication Failures

### 7.1 Information Leakage via Login Responses (CWE-204) - ASVS V6.3

```javascript
// ❌ Different messages reveal whether the account exists
app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(401).json({ error: "User not found" });
  if (!(await bcrypt.compare(req.body.password, user.hash))) {
    return res.status(401).json({ error: "Wrong password" });
  }
  res.json({ token: generateToken(user) });
});
```

```javascript
// ✅ Generic message regardless of failure reason
const bcrypt = require("bcrypt");

app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  const valid = user && (await bcrypt.compare(req.body.password, user.hash));

  if (!valid) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  res.json({ token: generateToken(user) });
});
```

**Rule:** Use identical error messages for "user not found" and "wrong password" to prevent user enumeration.

> **Note:** This fix has a subtle timing side-channel: requests for non-existent users return faster because `bcrypt.compare` is skipped. For high-security applications, call `bcrypt.compare` with a dummy hash when the user is not found to equalize response times.

---

### 7.2 Sensitive Data in Logs (CWE-532) - ASVS V16.2

```javascript
// ❌ Logging raw request body (may include passwords)
app.post("/login", async (req, res) => {
  console.log("Login attempt", req.body);
  // ...
});
```

```javascript
// ✅ Log only what's needed, redact sensitive fields
app.post("/login", async (req, res) => {
  const { username } = req.body;
  console.info("Login attempt", { username });
  // ...
});
```

**Rule:** Never log passwords, tokens, API keys, or PII. Destructure and select only safe fields.

---

## A08 - Software and Data Integrity Failures

### 8.1 Unsafe Deserialization (CWE-502) - ASVS V1.5

```javascript
// ❌ Deserializing untrusted data
const serialize = require("node-serialize");

app.post("/profile", express.text(), (req, res) => {
  const profile = serialize.unserialize(req.body);
  // Attacker can inject executable functions
  res.json(profile);
});
```

```javascript
// ✅ Use JSON.parse (no code execution) + schema validation
const Joi = require("joi");
const profileSchema = Joi.object({
  name: Joi.string().max(100).required(),
  email: Joi.string().email().required()
});

app.post("/profile", express.text(), (req, res) => {
  let parsed;
  try {
    parsed = JSON.parse(req.body);
  } catch {
    return res.status(400).json({ error: "Invalid JSON" });
  }
  const { error, value } = profileSchema.validate(parsed);
  if (error) return res.status(400).json({ error: error.message });
  res.json(value);
});
```

**Rule:** Never use `unserialize()` on untrusted data. Use `JSON.parse()` + schema validation (Joi, Zod, or Yup).

---

### 8.2 Prototype Pollution (CWE-1321) - ASVS V1.3

```javascript
// ❌ Deep merge of user input into objects
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
// Attacker sends: { "__proto__": { "isAdmin": true } }
```

```javascript
// ✅ Block dangerous keys during merge
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;  // skip dangerous keys
    }
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = safeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
// Or better: use Object.create(null) for config objects
```

**Rule:** Prototype pollution lets attackers inject properties into all objects. Block `__proto__`, `constructor`, and `prototype` in any merge/clone operation. Consider using `Object.create(null)` for lookup maps.

---

## A09 - Security Logging and Monitoring Failures

### 9.1 Insufficient Logging (CWE-778) - ASVS V16.2, V16.3

```javascript
// ❌ No security-relevant logging
app.post("/transfer", requireAuth, async (req, res) => {
  await db.query(
    "UPDATE accounts SET balance = balance - $1 WHERE id = $2",
    [req.body.amount, req.user.id]
  );
  res.json({ ok: true });
});
```

```javascript
// ✅ Structured security logging with context
const logger = require("pino")();

app.post("/transfer", requireAuth, async (req, res) => {
  const { amount, toAccount } = req.body;
  logger.info({
    event: "transfer_initiated",
    userId: req.user.id, amount, toAccount,
    ip: req.ip
  });
  await db.query(
    "UPDATE accounts SET balance = balance - $1 WHERE id = $2",
    [amount, req.user.id]
  );
  logger.info({
    event: "transfer_completed",
    userId: req.user.id, amount, toAccount
  });
  res.json({ ok: true });
});
```

**Rule:** Every security-relevant action should leave a trace: who, what, when, where, outcome. Use structured logging (JSON) for machine parseability.

---

### 9.2 What to Log vs What NOT to Log

**ALWAYS log:** Authentication events (login, logout, failed attempts), authorization failures (403s), input validation failures, system errors, administrative actions, access to sensitive resources.

**NEVER log:** Passwords or credentials, session tokens or API keys, full credit card numbers or PII, raw request bodies that may contain secrets.

**Each log entry should contain:** timestamp (ISO 8601), user identity, action performed, resource affected, outcome (success/failure), source IP / request ID.

---

## A10 - Server-Side Request Forgery (SSRF)

### 10.1 Unvalidated URL Fetching (CWE-918) - ASVS V1.2

```javascript
// ❌ Fetching any URL the user provides
const fetch = require("node-fetch");
app.get("/preview", async (req, res) => {
  const response = await fetch(req.query.url);
  const body = await response.text();
  res.send(body);
});
// Attacker sends: ?url=http://169.254.169.254/latest/meta-data/
// (AWS metadata endpoint - leaks IAM credentials)
```

```javascript
// ✅ URL allowlist + block private IP ranges
const { URL } = require("url");
const fetch = require("node-fetch");
const ipRangeCheck = require("ip-range-check");

const ALLOWED_HOSTS = ["api.trusted.com", "cdn.example.com"];
const PRIVATE_RANGES = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
  "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8"
];

app.get("/preview", async (req, res) => {
  let parsed;
  try {
    parsed = new URL(req.query.url);
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return res.status(400).json({ error: "Invalid protocol" });
  }
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    return res.status(403).json({ error: "Host not allowed" });
  }

  // Resolve DNS and check for private IPs (defense in depth)
  const dns = require("dns").promises;
  const { address } = await dns.lookup(parsed.hostname);
  if (ipRangeCheck(address, PRIVATE_RANGES)) {
    return res.status(403).json({ error: "Private IP not allowed" });
  }

  const response = await fetch(req.query.url);
  const body = await response.text();
  res.send(body);
});
```

**Rule:** Validate URL protocol, hostname against an allowlist, and resolved IP against private ranges. The AWS metadata endpoint (`169.254.169.254`) is the most common SSRF target in cloud environments.

---

## Additional Patterns (Not in OWASP Top 10)

### Fail-Secure Error Handling - ASVS V16.5

```javascript
// ❌ Authorization fails open on error
async function checkPermission(userId, resource) {
  try {
    const result = await db.query("SELECT role FROM users WHERE id = $1", [userId]);
    return result.rows[0]?.role === "admin";
  } catch (err) {
    return true;  // ❌ fail-open: error → allow
  }
}
```

```javascript
// ✅ Authorization fails closed on error
async function checkPermission(userId, resource) {
  try {
    const result = await db.query("SELECT role FROM users WHERE id = $1", [userId]);
    return result.rows[0]?.role === "admin";
  } catch (err) {
    console.error("Permission check failed", { userId, err: err.message });
    return false;  // ✅ fail-closed: error → deny
  }
}
```

**Rule:** In a failure scenario, the system should behave like an overprotective security guard, not an optimistic one.

---

### Regular Expression Denial of Service / ReDoS (CWE-1333) - ASVS V15.3

```javascript
// ❌ Evil regex - exponential backtracking on crafted input
const EMAIL_REGEX = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$/;
// Attacker sends: "aaaaaaaaaaaaaaaaaaaaaaaa!"
```

```javascript
// ✅ Use a well-tested validation library
const { isEmail } = require("validator");

if (!isEmail(req.body.email)) {
  return res.status(400).json({ error: "Invalid email" });
}
```

**Rule:** Don't write your own regex for common patterns. Use the `validator` library or `safe-regex` to check for catastrophic backtracking.

---

### Mass Assignment (CWE-915) - ASVS V2.2

```javascript
// ❌ Passing entire request body to database
app.post("/register", async (req, res) => {
  const user = await User.create(req.body);
  // Attacker sends: { "email": "a@b.com", "password": "...", "role": "admin" }
  res.json(user);
});
```

```javascript
// ✅ Explicitly pick allowed fields
app.post("/register", async (req, res) => {
  const { email, password, name } = req.body;  // only allowed fields
  const hash = await bcrypt.hash(password, 12);
  const user = await User.create({ email, name, passwordHash: hash, role: "user" });
  res.json({ id: user.id, email: user.email });
});
```

**Rule:** Never spread `req.body` into a model. Explicitly destructure only the fields you expect. Set sensitive defaults (like `role`) server-side.

---

## Quick Reference Table

| OWASP | Vulnerability | CWE | Fix |
|---|---|---|---|
| A01 | Missing Authorization | CWE-862 | Role check middleware on every privileged endpoint |
| A01 | IDOR | CWE-639 | Scope queries to authenticated user |
| A02 | Weak Password Hashing | CWE-916 | bcrypt / Argon2 with salt |
| A02 | Hardcoded Secrets | CWE-798 | Environment variables / secrets manager |
| A03 | SQL Injection | CWE-89 | Parameterized queries |
| A03 | NoSQL Injection | CWE-943 | Sanitize `$`-operators / type check inputs |
| A03 | XSS | CWE-79 | Context-aware output encoding |
| A03 | Command Injection | CWE-78 | `execFile()` + allowlist validation |
| A03 | Path Traversal | CWE-22 | `path.resolve()` + base directory check |
| A04 | No Rate Limiting | Design flaw | `express-rate-limit` on sensitive endpoints |
| A05 | Open CORS / Debug | CWE-16 | Environment-based config, Helmet.js |
| A05 | Missing Headers | CWE-16 | `app.use(helmet())` |
| A05 | Insecure Cookies | CWE-614 | secure, httpOnly, sameSite flags |
| A06 | Vulnerable Dependencies | - | `npm audit`, Snyk, Dependabot |
| A07 | User Enumeration | CWE-204 | Generic login failure messages |
| A07 | Logging Credentials | CWE-532 | Destructure, log only safe fields |
| A08 | Unsafe Deserialization | CWE-502 | `JSON.parse()` + schema validation |
| A08 | Prototype Pollution | CWE-1321 | Block `__proto__` / `constructor` keys |
| A09 | Insufficient Logging | CWE-778 | Structured logging for security events |
| A10 | SSRF | CWE-918 | URL allowlist + private IP blocking |
| - | Fail-Open Errors | CWE-636 | Always fail closed (deny on error) |
| - | ReDoS | CWE-1333 | `validator` library / `safe-regex` |
| - | Mass Assignment | CWE-915 | Explicit field selection from `req.body` |

---

*SSE - Secure Software Engineering | MESW 25/26 | FEUP*
*Version 1.0 - March 2026*

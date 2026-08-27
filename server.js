const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5900;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const APPS_FILE = path.join(DATA_DIR, "oauth-apps.json");
const SECRET_FILE = path.join(DATA_DIR, "oauth-secret.key");
const REVOKED_TOKENS_FILE = path.join(DATA_DIR, "revoked-tokens.json");
const SUCCESS_FILE = path.join(__dirname, "success.html");

fs.mkdirSync(DATA_DIR, { recursive: true });
for (const file of [USERS_FILE, APPS_FILE, REVOKED_TOKENS_FILE]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]");
}

let OAUTH_SECRET;
if (fs.existsSync(SECRET_FILE)) {
  OAUTH_SECRET = fs.readFileSync(SECRET_FILE, "utf8").trim();
} else {
  OAUTH_SECRET = crypto.randomBytes(64).toString("hex");
  fs.writeFileSync(SECRET_FILE, OAUTH_SECRET, { mode: 0o600 });
}

const deviceCodes = new Map();
const authorizationCodes = new Map();

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function generateClientId() {
  return "client_" + randomHex(16);
}

function generateClientSecret() {
  return "secret_" + randomHex(32);
}

function generateDeviceCode() {
  return crypto.randomBytes(4).toString("hex").toUpperCase();
}

function baseUrl(req) {
  const protocol = req.headers["x-forwarded-proto"] || req.protocol;
  return `${protocol}://${req.get("host")}`;
}

function isTokenRevoked(jti) {
  if (!jti) return false;
  return readJson(REVOKED_TOKENS_FILE).some(x => x.jti === jti);
}

function revokeToken(jti, exp) {
  const revoked = readJson(REVOKED_TOKENS_FILE);
  if (!revoked.some(x => x.jti === jti)) {
    revoked.push({ jti, exp: exp || null, revokedAt: new Date().toISOString() });
    writeJson(REVOKED_TOKENS_FILE, revoked);
  }
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function validPkceChallenge(challenge) {
  return typeof challenge === "string" && /^[A-Za-z0-9_-]{43,128}$/.test(challenge);
}

function verifyPkce(verifier, challenge, method) {
  if (method !== "S256" || typeof verifier !== "string") return false;
  const digest = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return safeEqual(digest, challenge);
}

function htmlEscape(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* -------------------- Login page -------------------- */
const loginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>
body{background:#111;color:#00ff66;font-family:monospace;padding:25px}
.box{max-width:520px;margin:auto;background:#1b1b1b;padding:25px;border-radius:8px}
input,button{width:100%;box-sizing:border-box;padding:12px;margin:6px 0;background:#222;color:#fff;border:1px solid #444;font-family:monospace}
button{background:#0088cc;border:0;font-weight:bold;cursor:pointer}
.small{color:#aaa;word-break:break-word}
</style>
</head>
<body>
<div class="box">
<h1>Sign in</h1>
<p id="app"></p>
<form method="POST" action="/authorize/consent">
<input type="hidden" name="client_id" id="client_id">
<input type="hidden" name="redirect_uri" id="redirect_uri">
<input type="hidden" name="response_type" id="response_type">
<input type="hidden" name="scope" id="scope">
<input type="hidden" name="state" id="state">
<input type="hidden" name="code_challenge" id="code_challenge">
<input type="hidden" name="code_challenge_method" id="code_challenge_method">
<input name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign in and authorize</button>
</form>
<p class="small">Only the registered redirect URI for the OAuth application can receive the authorization code.</p>
</div>
<script>
const q = new URLSearchParams(location.search);
for (const k of ["client_id","redirect_uri","response_type","scope","state","code_challenge","code_challenge_method"]) {
  const el=document.getElementById(k);
  if(el) el.value=q.get(k)||"";
}
document.getElementById("app").textContent = "Application: " + (q.get("client_id") || "Unknown");
</script>
</body>
</html>`;

app.get("/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;
  if (response_type !== "code") {
    return res.status(400).json({ error: "unsupported_response_type" });
  }
  if (!client_id || !redirect_uri) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (!validPkceChallenge(code_challenge) || code_challenge_method !== "S256") {
    return res.status(400).json({ error: "invalid_request", error_description: "PKCE S256 code_challenge is required." });
  }
  const oauthApp = readJson(APPS_FILE).find(x => x.client_id === client_id);
  if (!oauthApp) {
    return res.status(400).json({ error: "invalid_client" });
  }
  if (oauthApp.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }
  res.send(loginHtml);
});

app.post("/authorize/consent", (req, res) => {
  const { username, password, client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.body;
  if (response_type !== "code") {
    return res.status(400).send("Unsupported response type.");
  }
  if (!validPkceChallenge(code_challenge) || code_challenge_method !== "S256") {
    return res.status(400).send("Valid PKCE S256 parameters are required.");
  }
  const oauthApp = readJson(APPS_FILE).find(x => x.client_id === client_id);
  if (!oauthApp || oauthApp.redirect_uri !== redirect_uri) {
    return res.status(400).send("Invalid OAuth client or redirect URI.");
  }
  const user = readJson(USERS_FILE).find(
    u => u.username === username && u.passwordHash === hashPassword(password || "")
  );
  if (!user) {
    return res.status(401).send("Invalid username or password.");
  }
  const code = randomHex(32);
  authorizationCodes.set(code, {
    code,
    clientId: client_id,
    redirectUri: redirect_uri,
    userId: user.id,
    username: user.username,
    scope: scope || "",
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000
  });
  const callback = new URL(redirect_uri);
  callback.searchParams.set("code", code);
  if (state) callback.searchParams.set("state", state);
  res.redirect(callback.toString());
});

/* -------------------- Token endpoint: authorization_code + PKCE -------------------- */
app.post("/oauth2/token", (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, device_code } = req.body;
  
  if (device_code) {
    if (client_id) {
      const oauthApp = readJson(APPS_FILE).find(
        x => x.client_id === client_id && x.client_secret === client_secret
      );
      if (!oauthApp) return res.status(401).json({ error: "invalid_client" });
    }
    const device = deviceCodes.get(device_code);
    if (!device) return res.status(400).json({ error: "invalid_device_code" });
    if (Date.now() > device.expiresAt) {
      deviceCodes.delete(device_code);
      return res.status(400).json({ error: "expired_device_code" });
    }
    if (device.status === "pending") {
      return res.status(428).json({ error: "authorization_pending" });
    }
    if (device.status !== "approved") {
      return res.status(400).json({ error: "invalid_device_state" });
    }
    const accessToken = jwt.sign({
      sub: device.username,
      username: device.username,
      device_code: device.deviceCode,
      jti: randomHex(32)
    }, OAUTH_SECRET, { expiresIn: "1h" });
    deviceCodes.delete(device_code);
    return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600 });
  }

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }
  if (!code || !client_id || !redirect_uri || !code_verifier) {
    return res.status(400).json({ error: "invalid_request", error_description: "code, client_id, redirect_uri and code_verifier are required." });
  }
  const record = authorizationCodes.get(code);
  if (!record) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  
  authorizationCodes.delete(code);
  if (Date.now() > record.expiresAt) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Code expired." });
  }
  if (record.clientId !== client_id || record.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  if (!verifyPkce(code_verifier, record.codeChallenge, record.codeChallengeMethod)) {
    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed." });
  }
  
  const accessToken = jwt.sign({
    sub: record.userId,
    username: record.username,
    scope: record.scope,
    jti: randomHex(32)
  }, OAUTH_SECRET, { expiresIn: "1h" });
  
  return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, scope: record.scope });
});

/* -------------------- Device-code flow -------------------- */
app.post("/oauth/device/code", (req, res) => {
  const deviceCode = randomHex(32);
  const userCode = generateDeviceCode();
  const expiresIn = 600;
  deviceCodes.set(deviceCode, {
    deviceCode,
    userCode,
    clientId: req.body.client_id || null,
    username: null,
    status: "pending",
    createdAt: Date.now(),
    expiresAt: Date.now() + expiresIn * 1000
  });
  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${baseUrl(req)}/oauth/device`,
    verification_uri_complete: `${baseUrl(req)}/oauth/device?code=${userCode}`,
    expires_in: expiresIn,
    interval: 5
  });
});

app.get("/oauth/device", (req, res) => res.send(loginHtml));

app.post("/login/device", (req, res) => {
  const { device_code, username, password } = req.body;
  let device = null;
  for (const item of deviceCodes.values()) {
    if (item.deviceCode === device_code || item.userCode === String(device_code || "").toUpperCase()) {
      device = item;
      break;
    }
  }
  if (!device) return res.status(400).send("Invalid device code.");
  if (Date.now() > device.expiresAt) return res.status(400).send("Device code expired.");
  
  const user = readJson(USERS_FILE).find(
    u => u.username === username && u.passwordHash === hashPassword(password || "")
  );
  if (!user) return res.status(401).send("Invalid username or password.");
  
  device.status = "approved";
  device.username = username;
  res.redirect(`/login/device/success?device_code=${encodeURIComponent(device.deviceCode)}`);
});

app.get("/login/device/success", (req, res) => {
  const device = deviceCodes.get(req.query.device_code);
  if (!device) return res.status(404).send("Device code not found.");
  res.send(`<!DOCTYPE html><html><head><title>Device Connected</title>
<style>body{background:#111;color:#00ff66;font-family:monospace;padding:30px}.box{max-width:600px;margin:auto;background:#1b1b1b;padding:25px}</style>
</head><body><div class="box"><h1>Device Connected</h1>
<p>Account successfully connected.</p><p>Username: <strong>${htmlEscape(device.username)}</strong></p>
<p>You can return to your application.</p></div></body></html>`);
});

/* -------------------- Accounts -------------------- */
app.post("/api/auth/register", (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "username_and_password_required" });
  }
  if (username.length < 3 || password.length < 8) {
    return res.status(400).json({ error: "invalid_registration", message: "Username must contain at least 3 characters and password at least 8 characters." });
  }
  const users = readJson(USERS_FILE);
  if (users.some(u => u.username === username)) {
    return res.status(409).json({ error: "username_already_exists" });
  }
  users.push({
    id: randomHex(16),
    username,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString()
  });
  writeJson(USERS_FILE, users);
  res.status(201).json({ status: "success", username });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  const user = readJson(USERS_FILE).find(u => u.username === username);
  if (!user || user.passwordHash !== hashPassword(password || "")) {
    return res.status(401).json({ error: "invalid_credentials" });
  }
  const accessToken = jwt.sign({ sub: user.id, username: user.username, jti: randomHex(32) }, OAUTH_SECRET, { expiresIn: "1h" });
  res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600 });
});

/* -------------------- JWT protected endpoints -------------------- */
function authenticateJWT(req, res, next) {
  const authorization = req.headers.authorization || "";
  if (!authorization.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized", message: "Bearer access token required" });
  }
  try {
    const token = authorization.substring(7);
    const decoded = jwt.verify(token, OAUTH_SECRET);
    if (decoded.jti && isTokenRevoked(decoded.jti)) {
      return res.status(401).json({ error: "invalid_token", message: "Token has been logged out" });
    }
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token", message: "Invalid or expired access token" });
  }
}

app.post("/api/auth/logout", authenticateJWT, (req, res) => {
  if (!req.user.jti) return res.status(400).json({ error: "token_missing_jti" });
  revokeToken(req.user.jti, req.user.exp);
  res.json({ status: "success", message: "Logged out successfully" });
});

app.get(["/api/auth/me", "/api/whoami", "/oauth/userinfo"], authenticateJWT, (req, res) => {
  res.json({ authenticated: true, sub: req.user.sub, username: req.user.username, scope: req.user.scope || "", token_type: "Bearer" });
});

app.get("/api/get-ram", authenticateJWT, (req, res) => {
  res.json({ ram_mb: 1024, username: req.user.username });
});

app.get("/api/oauth/status", authenticateJWT, (req, res) => {
  res.json({ authenticated: true, username: req.user.username, token_type: "Bearer", scope: req.user.scope || "", ram_mb: 1024 });
});

/* -------------------- OAuth app registration -------------------- */
app.post(["/oauth/apps", "/create"], (req, res) => {
  const { name, redirect_uri } = req.body;
  if (!name || !redirect_uri) {
    return res.status(400).json({ error: "application_name_and_redirect_uri_required" });
  }
  let parsed;
  try {
    parsed = new URL(redirect_uri);
  } catch {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }
  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const apps = readJson(APPS_FILE);
  apps.push({
    id: randomHex(16),
    name,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri,
    createdAt: new Date().toISOString()
  });
  writeJson(APPS_FILE, apps);
  res.status(201).json({ status: "success", name, client_id: clientId, client_secret: clientSecret, redirect_uri });
});

app.get("/create", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Create OAuth App</title></head>
<body style="background:#111;color:#00ff66;font-family:monospace;padding:30px">
<h2>Register OAuth App</h2>
<form method="POST" action="/create">
<input name="name" placeholder="App Name" required style="padding:10px;background:#222;color:#fff;border:1px solid #444">
<input name="redirect_uri" placeholder="https://example.com/callback" required style="padding:10px;background:#222;color:#fff;border:1px solid #444">
<button style="padding:10px 20px;background:#0088cc;color:#fff;border:0">Create App</button>
</form></body></html>`);
});

/* -------------------- Success page -------------------- */
app.get("/success.html", (req, res) => {
  if (!fs.existsSync(SUCCESS_FILE)) {
    return res.status(404).send("success.html not found");
  }
  res.sendFile(SUCCESS_FILE);
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "oauth-pkce-server" });
});

app.use((req, res) => {
  res.status(404).json({ error: "not_found" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`OAuth server running on port ${PORT}`);
  console.log(`Authorize: http://localhost:${PORT}/authorize`);
  console.log(`Create app: http://localhost:${PORT}/create`);
});

import { NextResponse } from 'next/server';
import { MongoClient } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import tls from 'tls';
import net from 'net';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MONGO_URL = process.env.MONGO_URL;
const DB_NAME = process.env.DB_NAME || 'security_platform';

let cached = global._mongo;
if (!cached) cached = global._mongo = { client: null, db: null };

async function getDb() {
  if (cached.db) return cached.db;
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  cached.client = client;
  cached.db = client.db(DB_NAME);
  return cached.db;
}

const json = (data, status = 200) =>
  NextResponse.json(data, {
    status,
    headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' },
  });

// ============================================================
// SCANNER ENGINE (real, non-intrusive)
// ============================================================
const SEV_WEIGHT = { Critical: 30, High: 18, Medium: 8, Low: 3, Info: 0 };

function normalizeUrl(input) {
  let u = String(input || '').trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}

async function fetchWithTimeout(url, opts = {}, ms = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      redirect: 'follow',
      signal: ctrl.signal,
      headers: { 'User-Agent': 'SentinelScanner/1.0 (+security-audit)' },
      ...opts,
    });
  } finally {
    clearTimeout(t);
  }
}

function mkFinding(o) {
  return {
    id: uuidv4(),
    title: o.title,
    severity: o.severity,
    category: o.category,
    cwe: o.cwe || null,
    cve: o.cve || null,
    description: o.description,
    evidence: o.evidence || '',
    endpoint: o.endpoint || '',
    checkKey: o.checkKey || '',
    status: 'Open',
    createdAt: new Date().toISOString(),
  };
}

// ---- Framework-aware remediation library ----
const REMEDIATION = {
  'strict-transport-security': {
    generic: "Send: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    CodeIgniter: "// app/Config/Filters or .htaccess\nHeader always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"",
    NestJS: "import helmet from 'helmet';\napp.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));",
    Go: `w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")`,
  },
  'content-security-policy': {
    generic: "Define a strict Content-Security-Policy, e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    CodeIgniter: "$config['csp_enabled'] = TRUE; // app/Config/App.php  (CI4 native CSP)",
    NestJS: "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"] } }));",
    Go: `w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'")`,
  },
  'x-frame-options': {
    generic: "Send: X-Frame-Options: DENY (or SAMEORIGIN)",
    CodeIgniter: `$response->setHeader('X-Frame-Options', 'DENY');`,
    NestJS: "app.use(helmet.frameguard({ action: 'deny' }));",
    Go: `w.Header().Set("X-Frame-Options", "DENY")`,
  },
  'x-content-type-options': {
    generic: "Send: X-Content-Type-Options: nosniff",
    CodeIgniter: `$response->setHeader('X-Content-Type-Options', 'nosniff');`,
    NestJS: "app.use(helmet.noSniff());",
    Go: `w.Header().Set("X-Content-Type-Options", "nosniff")`,
  },
  'referrer-policy': {
    generic: "Send: Referrer-Policy: strict-origin-when-cross-origin",
    CodeIgniter: `$response->setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');`,
    NestJS: "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
    Go: `w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")`,
  },
  'permissions-policy': {
    generic: "Send: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    CodeIgniter: `$response->setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');`,
    NestJS: `res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');`,
    Go: `w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")`,
  },
  'x-powered-by': {
    generic: "Remove framework/version disclosure headers.",
    CodeIgniter: "// Remove in .htaccess\nHeader unset X-Powered-By\n// php.ini: expose_php = Off",
    NestJS: "app.disable('x-powered-by'); // or app.use(helmet.hidePoweredBy());",
    Go: "// Do not set Server / X-Powered-By headers; strip them at the reverse proxy.",
  },
  'server': {
    generic: "Suppress or genericize the Server header at the web server / reverse proxy.",
    CodeIgniter: "# Apache: ServerTokens Prod\n# Nginx: server_tokens off;",
    NestJS: "// Strip 'Server' header at Nginx: server_tokens off;",
    Go: "// Avoid setting Server header; sanitize at reverse proxy.",
  },
  'cookie': {
    generic: "Set cookies with Secure; HttpOnly; SameSite=Strict (or Lax).",
    CodeIgniter: "$config['cookie_secure'] = TRUE;\n$config['cookie_httponly'] = TRUE;\n$config['cookie_samesite'] = 'Lax'; // app/Config/App.php",
    NestJS: "res.cookie('sid', v, { secure: true, httpOnly: true, sameSite: 'strict' });",
    Go: `http.SetCookie(w, &http.Cookie{Name:"sid", Secure:true, HttpOnly:true, SameSite: http.SameSiteStrictMode})`,
  },
  'tls-protocol': {
    generic: "Disable TLS 1.0/1.1. Require TLS 1.2+ with modern ciphers.",
    CodeIgniter: "# Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
    NestJS: "// Terminate TLS at Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
    Go: "tls.Config{ MinVersion: tls.VersionTLS12 }",
  },
  'tls-expiry': {
    generic: "Renew the certificate and automate renewal (e.g. certbot / ACME).",
    CodeIgniter: "# certbot renew --deploy-hook 'systemctl reload nginx'",
    NestJS: "# Automate via certbot / Caddy auto-HTTPS.",
    Go: "// Use golang.org/x/crypto/acme/autocert for auto renewal.",
  },
  'tls-invalid': {
    generic: "Install a certificate from a trusted CA matching the hostname.",
    CodeIgniter: "# Use Let's Encrypt: certbot --nginx -d example.com",
    NestJS: "# Issue a valid cert via certbot / Caddy.",
    Go: "// Use autocert.Manager with a valid domain.",
  },
  'sensitive-file': {
    generic: "Block public access to the file and move secrets outside the web root.",
    CodeIgniter: "# .htaccess\n<FilesMatch \"^\\.(env|git)\">\n  Require all denied\n</FilesMatch>",
    NestJS: "// Never serve dotfiles; keep .env out of served static dirs.\n// Nginx: location ~ /\\. { deny all; }",
    Go: "// Do not register static routes for dotfiles; deny at proxy: location ~ /\\. { deny all; }",
  },
  'csrf': {
    generic: "Enable CSRF protection framework-wide.",
    CodeIgniter: "$config['csrf_protection'] = TRUE; // CI3 app/config/config.php\n// CI4: enable 'csrf' in app/Config/Filters.php",
    NestJS: "import * as csurf from 'csurf';\napp.use(csurf());",
    Go: "// gorilla/csrf: r.Use(csrf.Protect([]byte(key)))",
  },
  'port-exposure': {
    generic: "Restrict the service to localhost/VPC and add firewall rules to block public access.",
    CodeIgniter: "# ufw deny 3306 ; bind-address = 127.0.0.1 in my.cnf",
    NestJS: "# Bind DB/Redis to private network; GCP firewall: deny 0.0.0.0/0 to sensitive ports.",
    Go: "# Restrict via GCP firewall / Proxmox firewall to trusted CIDRs only.",
  },
};

function remediationFor(checkKey, framework) {
  const r = REMEDIATION[checkKey];
  if (!r) return { generic: 'Review and apply the relevant security control.', snippet: '', framework };
  const snippet = r[framework] || r.CodeIgniter || '';
  return { generic: r.generic, snippet, framework };
}

function analyzeSecurityHeaders(headers, baseUrl) {
  const findings = [];
  const get = (k) => headers.get(k);
  const checks = [
    { key: 'strict-transport-security', name: 'HTTP Strict Transport Security (HSTS)', sev: 'High', cwe: 'CWE-319', desc: 'HSTS header is missing. Connections may be downgraded to plain HTTP, exposing users to man-in-the-middle attacks.' },
    { key: 'content-security-policy', name: 'Content Security Policy (CSP)', sev: 'Medium', cwe: 'CWE-693', desc: 'No Content-Security-Policy header found. The application is more exposed to XSS and content-injection attacks.' },
    { key: 'x-frame-options', name: 'X-Frame-Options', sev: 'Medium', cwe: 'CWE-1021', desc: 'Missing X-Frame-Options header allows the page to be framed, enabling clickjacking.' },
    { key: 'x-content-type-options', name: 'X-Content-Type-Options', sev: 'Low', cwe: 'CWE-693', desc: 'Missing "nosniff" allows browsers to MIME-sniff responses, which can lead to drive-by attacks.' },
    { key: 'referrer-policy', name: 'Referrer-Policy', sev: 'Low', cwe: 'CWE-200', desc: 'No Referrer-Policy set; full URLs (possibly with tokens) may leak to third-party sites.' },
    { key: 'permissions-policy', name: 'Permissions-Policy', sev: 'Low', cwe: 'CWE-693', desc: 'No Permissions-Policy to restrict powerful browser features (camera, mic, geolocation).' },
  ];
  for (const c of checks) {
    if (!get(c.key)) {
      findings.push(mkFinding({ title: `Missing ${c.name}`, severity: c.sev, category: 'HTTP Headers', cwe: c.cwe, description: c.desc, evidence: `Response headers for ${baseUrl} did not include "${c.key}".`, endpoint: baseUrl, checkKey: c.key }));
    }
  }
  const xpb = get('x-powered-by');
  if (xpb) findings.push(mkFinding({ title: 'Technology disclosure via X-Powered-By', severity: 'Low', category: 'Info Disclosure', cwe: 'CWE-200', description: `The server discloses backend technology, aiding targeted attacks: ${xpb}`, evidence: `X-Powered-By: ${xpb}`, endpoint: baseUrl, checkKey: 'x-powered-by' }));
  const server = get('server');
  if (server && /\d/.test(server)) findings.push(mkFinding({ title: 'Server version disclosure', severity: 'Low', category: 'Info Disclosure', cwe: 'CWE-200', description: `The Server header reveals software and version, useful for attackers: ${server}`, evidence: `Server: ${server}`, endpoint: baseUrl, checkKey: 'server' }));
  return findings;
}

function analyzeCookies(headers, baseUrl) {
  let cookies = [];
  try { cookies = headers.getSetCookie ? headers.getSetCookie() : []; } catch (e) { cookies = []; }
  if (!cookies.length) { const sc = headers.get('set-cookie'); if (sc) cookies = [sc]; }
  const findings = [];
  for (const ck of cookies) {
    const name = String(ck).split('=')[0];
    const low = String(ck).toLowerCase();
    const missing = [];
    if (!low.includes('secure')) missing.push('Secure');
    if (!low.includes('httponly')) missing.push('HttpOnly');
    if (!low.includes('samesite')) missing.push('SameSite');
    if (missing.length) {
      findings.push(mkFinding({ title: `Insecure cookie flags on "${name}"`, severity: missing.includes('HttpOnly') ? 'Medium' : 'Low', category: 'Cookies', cwe: 'CWE-1004', description: `Session/cookie "${name}" is missing flags: ${missing.join(', ')}. This exposes it to theft via XSS or transport interception.`, evidence: String(ck).slice(0, 140), endpoint: baseUrl, checkKey: 'cookie' }));
    }
  }
  return findings;
}

function checkTLS(hostname, port = 443) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let socket;
    try {
      socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 8000 }, () => {
        const cert = socket.getPeerCertificate() || {};
        const protocol = socket.getProtocol();
        const now = Date.now();
        const validTo = cert.valid_to ? new Date(cert.valid_to).getTime() : null;
        const daysLeft = validTo ? Math.round((validTo - now) / 86400000) : null;
        const authorized = socket.authorized;
        const authError = socket.authorizationError ? String(socket.authorizationError) : null;
        finish({ ok: true, protocol, issuer: (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || 'Unknown', subject: (cert.subject && cert.subject.CN) || hostname, validFrom: cert.valid_from || null, validTo: cert.valid_to || null, daysLeft, authorized, authError });
        try { socket.end(); } catch (e) {}
      });
      socket.on('error', (e) => finish({ ok: false, error: e.message }));
      socket.on('timeout', () => { try { socket.destroy(); } catch (e) {} finish({ ok: false, error: 'connection timeout' }); });
    } catch (e) {
      finish({ ok: false, error: e.message });
    }
  });
}

function tlsFindings(tlsResult, baseUrl) {
  const findings = [];
  if (!tlsResult || !tlsResult.ok) return findings;
  const { protocol, daysLeft, authorized, authError } = tlsResult;
  if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
    findings.push(mkFinding({ title: `Deprecated TLS protocol in use (${protocol})`, severity: 'High', category: 'SSL/TLS', cwe: 'CWE-327', description: `The server negotiated ${protocol}, which is deprecated and vulnerable. Require TLS 1.2 or higher.`, evidence: `Negotiated protocol: ${protocol}`, endpoint: baseUrl, checkKey: 'tls-protocol' }));
  }
  if (typeof daysLeft === 'number') {
    if (daysLeft < 0) findings.push(mkFinding({ title: 'SSL/TLS certificate has EXPIRED', severity: 'Critical', category: 'SSL/TLS', cwe: 'CWE-298', description: `The certificate expired ${Math.abs(daysLeft)} day(s) ago. Users will see browser warnings and connections are untrusted.`, evidence: `valid_to: ${tlsResult.validTo}`, endpoint: baseUrl, checkKey: 'tls-expiry' }));
    else if (daysLeft < 15) findings.push(mkFinding({ title: 'SSL/TLS certificate expiring imminently', severity: 'High', category: 'SSL/TLS', cwe: 'CWE-298', description: `Certificate expires in ${daysLeft} day(s). Renew now to avoid an outage.`, evidence: `valid_to: ${tlsResult.validTo}`, endpoint: baseUrl, checkKey: 'tls-expiry' }));
    else if (daysLeft < 30) findings.push(mkFinding({ title: 'SSL/TLS certificate expiring soon', severity: 'Medium', category: 'SSL/TLS', cwe: 'CWE-298', description: `Certificate expires in ${daysLeft} day(s). Schedule renewal.`, evidence: `valid_to: ${tlsResult.validTo}`, endpoint: baseUrl, checkKey: 'tls-expiry' }));
  }
  if (authorized === false) {
    findings.push(mkFinding({ title: 'Untrusted / invalid TLS certificate', severity: 'High', category: 'SSL/TLS', cwe: 'CWE-295', description: `The certificate chain could not be validated (${authError || 'unknown reason'}). This may indicate a self-signed cert or hostname mismatch.`, evidence: authError || 'authorization failed', endpoint: baseUrl, checkKey: 'tls-invalid' }));
  }
  return findings;
}

const SENSITIVE_PATHS = [
  { path: '/.env', sev: 'Critical', sig: ['APP_KEY', 'DB_PASSWORD', 'DB_HOST', 'SECRET', 'APP_ENV'] },
  { path: '/.git/config', sev: 'High', sig: ['[core]', 'repositoryformatversion'] },
  { path: '/phpinfo.php', sev: 'High', sig: ['phpinfo()', 'PHP Version', 'php.ini'] },
  { path: '/config.php', sev: 'Medium', sig: ['<?php', 'define(', '$config'] },
  { path: '/.DS_Store', sev: 'Low', sig: [] },
  { path: '/server-status', sev: 'Medium', sig: ['Apache Server Status', 'Server uptime'] },
  { path: '/storage/logs/laravel.log', sev: 'High', sig: ['stack trace', 'ERROR', 'exception'] },
  { path: '/.env.bak', sev: 'Critical', sig: ['APP_KEY', 'DB_PASSWORD', 'SECRET'] },
];

async function probeSensitiveFiles(origin) {
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async (item) => {
      const url = origin.replace(/\/$/, '') + item.path;
      try {
        const res = await fetchWithTimeout(url, {}, 7000);
        if (res.status !== 200) return null;
        let body = '';
        try { body = (await res.text()).slice(0, 4000); } catch (e) { body = ''; }
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        // avoid false positives from SPA/HTML catch-all pages
        const looksHtmlApp = ct.includes('text/html') && /<html|<!doctype html/i.test(body) && item.sig.length > 0;
        const sigHit = item.sig.length === 0 ? !looksHtmlApp : item.sig.some((s) => body.toLowerCase().includes(s.toLowerCase()));
        if (!sigHit) return null;
        return mkFinding({
          title: `Exposed sensitive file: ${item.path}`,
          severity: item.sev,
          category: 'Exposed Files',
          cwe: 'CWE-538',
          description: `The file ${item.path} is publicly reachable and returned HTTP 200 with matching content. This can leak credentials, source, or internal data.`,
          evidence: `${url} -> 200 (${ct || 'unknown type'})`,
          endpoint: url,
          checkKey: 'sensitive-file',
        });
      } catch (e) { return null; }
    })
  );
  return results.filter(Boolean);
}

function tcpProbe(host, port, ms = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open) => { if (!settled) { settled = true; try { socket.destroy(); } catch (e) {} resolve(open); } };
    socket.setTimeout(ms);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    try { socket.connect(port, host); } catch (e) { done(false); }
  });
}

const RISKY_PORTS = [
  { port: 3306, name: 'MySQL', sev: 'Critical' },
  { port: 6379, name: 'Redis', sev: 'Critical' },
  { port: 27017, name: 'MongoDB', sev: 'Critical' },
  { port: 5432, name: 'PostgreSQL', sev: 'High' },
  { port: 8006, name: 'Proxmox Web UI', sev: 'High' },
  { port: 9200, name: 'Elasticsearch', sev: 'High' },
];

async function scanPorts(host) {
  const findings = [];
  const checked = [];
  await Promise.all(RISKY_PORTS.map(async (p) => {
    const open = await tcpProbe(host, p.port);
    checked.push({ port: p.port, name: p.name, open });
    if (open) {
      findings.push(mkFinding({ title: `Publicly exposed ${p.name} port (${p.port})`, severity: p.sev, category: 'Port Exposure', cwe: 'CWE-668', description: `TCP port ${p.port} (${p.name}) is reachable from the public internet. Data services should never be exposed publicly.`, evidence: `${host}:${p.port} is OPEN`, endpoint: `${host}:${p.port}`, checkKey: 'port-exposure' }));
    }
  }));
  return { findings, checked };
}

async function runScan({ url, framework = 'CodeIgniter' }) {
  const started = Date.now();
  const target = normalizeUrl(url);
  const parsed = new URL(target);
  const origin = parsed.origin;
  const hostname = parsed.hostname;
  const isHttps = parsed.protocol === 'https:';

  let findings = [];
  let headersSummary = {};
  let reachable = true;
  let statusCode = null;

  // 1. Headers + cookies
  try {
    const res = await fetchWithTimeout(target, {}, 10000);
    statusCode = res.status;
    res.headers.forEach((v, k) => { headersSummary[k] = v; });
    findings = findings.concat(analyzeSecurityHeaders(res.headers, target));
    findings = findings.concat(analyzeCookies(res.headers, target));
  } catch (e) {
    reachable = false;
    findings.push(mkFinding({ title: 'Target unreachable during header scan', severity: 'Info', category: 'Connectivity', description: `Could not fetch ${target}: ${e.message}`, evidence: e.message, endpoint: target, checkKey: '' }));
  }

  // 2. TLS
  let tlsResult = null;
  if (isHttps) {
    tlsResult = await checkTLS(hostname);
    findings = findings.concat(tlsFindings(tlsResult, target));
  } else {
    findings.push(mkFinding({ title: 'Site served over plaintext HTTP', severity: 'High', category: 'SSL/TLS', cwe: 'CWE-319', description: 'The target is served over HTTP without transport encryption. All traffic can be intercepted.', evidence: target, endpoint: target, checkKey: 'strict-transport-security' }));
  }

  // 3. Sensitive files
  const fileFindings = await probeSensitiveFiles(origin);
  findings = findings.concat(fileFindings);

  // 4. Ports
  const portScan = await scanPorts(hostname);
  findings = findings.concat(portScan.findings);

  // attach remediation
  findings = findings.map((f) => ({ ...f, remediation: remediationFor(f.checkKey, framework) }));

  // score
  let penalty = 0;
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) { counts[f.severity] = (counts[f.severity] || 0) + 1; penalty += SEV_WEIGHT[f.severity] || 0; }
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 45 ? 'D' : 'F';

  return {
    url: target, origin, hostname, framework,
    reachable, statusCode, isHttps,
    tls: tlsResult,
    headers: headersSummary,
    ports: portScan.checked,
    findings,
    counts,
    score,
    grade,
    durationMs: Date.now() - started,
    scannedAt: new Date().toISOString(),
  };
}

// ============================================================
// SEED DATA (mock inventory / infra / trend)
// ============================================================
function daysAgo(n) { const d = new Date(); d.setDate(d.getDate() - n); return d; }

async function ensureSeed(db) {
  // atomic claim so concurrent requests don't double-seed
  const meta = db.collection('meta');
  const claim = await meta.findOneAndUpdate(
    { _id: 'seed' },
    { $setOnInsert: { done: true, at: new Date() } },
    { upsert: true, returnDocument: 'before' }
  );
  const prev = claim && (claim.value !== undefined ? claim.value : claim);
  if (prev) return; // already seeded (or being seeded)

  const assetsCol = db.collection('assets');
  const count = await assetsCol.countDocuments({});
  if (count > 0) return;

  const now = new Date();
  const demoAssets = [
    { name: 'Corporate CMS', url: 'https://cms.acme-corp.example', framework: 'CodeIgniter', environment: 'Production', host: 'Proxmox', score: 72, demo: true },
    { name: 'Payments API', url: 'https://api.acme-pay.example', framework: 'NestJS', environment: 'Production', host: 'GCP', score: 58, demo: true },
    { name: 'Ledger Service', url: 'https://ledger.acme.example', framework: 'Go', environment: 'Staging', host: 'GCP', score: 88, demo: true },
    { name: 'Marketing Site', url: 'https://www.acme.example', framework: 'CodeIgniter', environment: 'Production', host: 'Proxmox', score: 64, demo: true },
    { name: 'Internal Admin', url: 'https://admin.acme.internal', framework: 'NestJS', environment: 'Staging', host: 'Proxmox', score: 41, demo: true },
  ];
  const assetDocs = demoAssets.map((a) => ({ id: uuidv4(), ...a, status: 'Active', lastScanned: daysAgo(Math.floor(Math.random() * 3)).toISOString(), createdAt: now.toISOString() }));
  await assetsCol.insertMany(assetDocs);

  const findingTemplates = [
    { title: 'Exposed sensitive file: /.env', severity: 'Critical', category: 'Exposed Files', cwe: 'CWE-538', description: 'The .env file is publicly reachable and leaks database credentials.', endpoint: '/.env', checkKey: 'sensitive-file' },
    { title: 'SSL/TLS certificate expiring soon', severity: 'High', category: 'SSL/TLS', cwe: 'CWE-298', description: 'Certificate expires in 12 days.', endpoint: '/', checkKey: 'tls-expiry' },
    { title: 'Missing HTTP Strict Transport Security (HSTS)', severity: 'High', category: 'HTTP Headers', cwe: 'CWE-319', description: 'HSTS header not present.', endpoint: '/', checkKey: 'strict-transport-security' },
    { title: 'Publicly exposed Redis port (6379)', severity: 'Critical', category: 'Port Exposure', cwe: 'CWE-668', description: 'Redis reachable from the internet with no auth.', endpoint: ':6379', checkKey: 'port-exposure' },
    { title: 'Missing Content Security Policy (CSP)', severity: 'Medium', category: 'HTTP Headers', cwe: 'CWE-693', description: 'No CSP configured.', endpoint: '/', checkKey: 'content-security-policy' },
    { title: 'Insecure cookie flags on "session"', severity: 'Medium', category: 'Cookies', cwe: 'CWE-1004', description: 'Missing HttpOnly and SameSite.', endpoint: '/', checkKey: 'cookie' },
    { title: 'CSRF protection disabled', severity: 'High', category: 'Framework Config', cwe: 'CWE-352', description: 'Framework CSRF protection is turned off.', endpoint: '/', checkKey: 'csrf' },
    { title: 'Technology disclosure via X-Powered-By', severity: 'Low', category: 'Info Disclosure', cwe: 'CWE-200', description: 'Backend framework disclosed.', endpoint: '/', checkKey: 'x-powered-by' },
    { title: 'Missing X-Frame-Options', severity: 'Medium', category: 'HTTP Headers', cwe: 'CWE-1021', description: 'Clickjacking possible.', endpoint: '/', checkKey: 'x-frame-options' },
    { title: 'Deprecated TLS protocol in use (TLSv1.1)', severity: 'High', category: 'SSL/TLS', cwe: 'CWE-327', description: 'Server negotiates TLS 1.1.', endpoint: '/', checkKey: 'tls-protocol' },
  ];
  const statuses = ['Open', 'Open', 'Open', 'In Progress', 'Resolved', 'False Positive'];
  const findingDocs = [];
  for (const a of assetDocs) {
    const n = 2 + Math.floor(Math.random() * 5);
    for (let i = 0; i < n; i++) {
      const t = findingTemplates[Math.floor(Math.random() * findingTemplates.length)];
      findingDocs.push({
        id: uuidv4(), assetId: a.id, assetName: a.name, framework: a.framework,
        ...t,
        remediation: remediationFor(t.checkKey, a.framework),
        status: statuses[Math.floor(Math.random() * statuses.length)],
        createdAt: daysAgo(Math.floor(Math.random() * 20)).toISOString(),
      });
    }
  }
  await db.collection('findings').insertMany(findingDocs);

  // 30-day trend scans
  const scanDocs = [];
  for (let d = 30; d >= 0; d--) {
    const base = 55 + (30 - d) * 0.8;
    for (const a of assetDocs) {
      const jitter = (Math.random() - 0.5) * 10;
      scanDocs.push({ id: uuidv4(), assetId: a.id, url: a.url, framework: a.framework, score: Math.max(20, Math.min(98, Math.round(base + jitter))), createdAt: daysAgo(d).toISOString(), demo: true, counts: {} });
    }
  }
  await db.collection('scans').insertMany(scanDocs);

  // infra nodes
  const infra = [
    { id: uuidv4(), name: 'gcp-web-prod-1', kind: 'GCP', type: 'Compute Instance', region: 'us-central1', publicIp: '34.121.44.10', status: 'Healthy', openPorts: [80, 443], tls: 'Valid (312d)', firewall: 'Compliant', issues: 0 },
    { id: uuidv4(), name: 'gcp-api-prod-2', kind: 'GCP', type: 'Compute Instance', region: 'europe-west1', publicIp: '35.204.19.88', status: 'At Risk', openPorts: [80, 443, 6379], tls: 'Valid (12d)', firewall: 'Redis (6379) open to 0.0.0.0/0', issues: 2 },
    { id: uuidv4(), name: 'gcp-metadata-audit', kind: 'GCP', type: 'Metadata Service', region: 'us-central1', publicIp: '—', status: 'Healthy', openPorts: [], tls: 'n/a', firewall: 'Metadata concealment ON', issues: 0 },
    { id: uuidv4(), name: 'pve-node-01', kind: 'Proxmox', type: 'Hypervisor Node', region: 'dc-rack-a', publicIp: '203.0.113.20', status: 'At Risk', openPorts: [22, 8006], tls: 'Self-signed', firewall: 'Web UI (8006) publicly reachable', issues: 2 },
    { id: uuidv4(), name: 'pve-ct-cms', kind: 'Proxmox', type: 'LXC Container', region: 'dc-rack-a', publicIp: '203.0.113.21', status: 'Healthy', openPorts: [80, 443], tls: 'Valid (201d)', firewall: 'Compliant', issues: 0 },
    { id: uuidv4(), name: 'pve-vm-db', kind: 'Proxmox', type: 'VM (MySQL)', region: 'dc-rack-b', publicIp: '203.0.113.22', status: 'Critical', openPorts: [22, 3306], tls: 'n/a', firewall: 'MySQL (3306) exposed + SSH brute-force detected', issues: 3 },
  ];
  await db.collection('infra_nodes').insertMany(infra);
}

// ============================================================
// ROUTER
// ============================================================
async function handle(request, ctx, method) {
  try {
    const params = await ctx.params;
    const segs = params?.path || [];
    const p0 = segs[0] || '';
    const p1 = segs[1] || '';
    const db = await getDb();

    // health / root
    if (!p0) return json({ name: 'Sentinel API', status: 'ok' });

    // ---- SEED ----
    if (p0 === 'seed') { await ensureSeed(db); return json({ seeded: true }); }

    // ---- SCAN (real) ----
    if (p0 === 'scan' && method === 'POST') {
      const body = await request.json();
      if (!body?.url) return json({ error: 'url is required' }, 400);
      const result = await runScan({ url: body.url, framework: body.framework || 'CodeIgniter' });

      // upsert asset
      const assetsCol = db.collection('assets');
      let asset = await assetsCol.findOne({ url: result.url });
      if (!asset) {
        asset = { id: uuidv4(), name: body.name || result.hostname, url: result.url, framework: result.framework, environment: body.environment || 'Production', host: body.host || 'GCP', status: 'Active', createdAt: new Date().toISOString() };
        await assetsCol.insertOne(asset);
      }
      await assetsCol.updateOne({ id: asset.id }, { $set: { score: result.score, lastScanned: result.scannedAt, framework: result.framework } });

      const scanId = uuidv4();
      await db.collection('scans').insertOne({ id: scanId, assetId: asset.id, url: result.url, framework: result.framework, score: result.score, grade: result.grade, counts: result.counts, tls: result.tls, ports: result.ports, headers: result.headers, durationMs: result.durationMs, createdAt: result.scannedAt });

      // store findings for the vuln center
      if (result.findings.length) {
        const docs = result.findings.map((f) => ({ ...f, assetId: asset.id, assetName: asset.name, scanId, framework: result.framework }));
        await db.collection('findings').insertMany(docs);
      }
      return json({ scanId, assetId: asset.id, ...result });
    }

    // ---- ASSETS ----
    if (p0 === 'assets') {
      const col = db.collection('assets');
      if (method === 'GET') { const items = await col.find({}, { projection: { _id: 0 } }).sort({ createdAt: -1 }).toArray(); return json(items); }
      if (method === 'POST') { const b = await request.json(); const doc = { id: uuidv4(), name: b.name, url: normalizeUrl(b.url), framework: b.framework || 'CodeIgniter', environment: b.environment || 'Production', host: b.host || 'GCP', status: 'Active', score: null, lastScanned: null, createdAt: new Date().toISOString() }; await col.insertOne(doc); const { _id, ...clean } = doc; return json(clean, 201); }
      if (method === 'DELETE' && p1) { await col.deleteOne({ id: p1 }); await db.collection('findings').deleteMany({ assetId: p1 }); return json({ deleted: true }); }
    }

    // ---- SCANS ----
    if (p0 === 'scans') {
      const col = db.collection('scans');
      if (method === 'GET' && p1) { const s = await col.findOne({ id: p1 }, { projection: { _id: 0 } }); if (!s) return json({ error: 'not found' }, 404); const findings = await db.collection('findings').find({ scanId: p1 }, { projection: { _id: 0 } }).toArray(); return json({ ...s, findings }); }
      if (method === 'GET') { const q = new URL(request.url).searchParams; const filter = {}; if (q.get('assetId')) filter.assetId = q.get('assetId'); const items = await col.find(filter, { projection: { _id: 0 } }).sort({ createdAt: -1 }).limit(50).toArray(); return json(items); }
    }

    // ---- FINDINGS ----
    if (p0 === 'findings') {
      const col = db.collection('findings');
      if (method === 'GET') { const items = await col.find({}, { projection: { _id: 0 } }).sort({ createdAt: -1 }).limit(500).toArray(); return json(items); }
      if (method === 'PATCH' && p1) { const b = await request.json(); await col.updateOne({ id: p1 }, { $set: { status: b.status } }); const updated = await col.findOne({ id: p1 }, { projection: { _id: 0 } }); return json(updated); }
    }

    // ---- DASHBOARD ----
    if (p0 === 'dashboard' && method === 'GET') {
      await ensureSeed(db);
      const assets = await db.collection('assets').find({}, { projection: { _id: 0 } }).toArray();
      const findings = await db.collection('findings').find({}, { projection: { _id: 0 } }).toArray();
      const openFindings = findings.filter((f) => f.status === 'Open' || f.status === 'In Progress');
      const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      for (const f of openFindings) if (bySeverity[f.severity] != null) bySeverity[f.severity]++;
      const scored = assets.filter((a) => typeof a.score === 'number');
      const avgScore = scored.length ? Math.round(scored.reduce((s, a) => s + a.score, 0) / scored.length) : 0;

      // trend from scans, grouped by day (avg)
      const scans = await db.collection('scans').find({}, { projection: { _id: 0, createdAt: 1, score: 1 } }).toArray();
      const byDay = {};
      for (const s of scans) { const day = (s.createdAt || '').slice(0, 10); if (!day || typeof s.score !== 'number') continue; (byDay[day] = byDay[day] || []).push(s.score); }
      const trend = Object.keys(byDay).sort().slice(-30).map((day) => ({ date: day.slice(5), score: Math.round(byDay[day].reduce((a, b) => a + b, 0) / byDay[day].length) }));

      const infra = await db.collection('infra_nodes').find({}, { projection: { _id: 0 } }).toArray();
      const infraIssues = infra.reduce((s, n) => s + (n.issues || 0), 0);
      const statusWorkflow = { Open: 0, 'In Progress': 0, Resolved: 0, 'False Positive': 0 };
      for (const f of findings) if (statusWorkflow[f.status] != null) statusWorkflow[f.status]++;

      return json({ avgScore, totalAssets: assets.length, bySeverity, trend, infraNodes: infra.length, infraIssues, statusWorkflow, criticalOpen: bySeverity.Critical, highOpen: bySeverity.High });
    }

    // ---- INFRA ----
    if (p0 === 'infra' && method === 'GET') { await ensureSeed(db); const items = await db.collection('infra_nodes').find({}, { projection: { _id: 0 } }).toArray(); return json(items); }

    // ---- SETTINGS (keys vault) ----
    if (p0 === 'settings') {
      const col = db.collection('settings');
      if (method === 'GET') { const s = await col.findOne({ id: 'global' }, { projection: { _id: 0 } }); const mask = (v) => (v ? '•'.repeat(Math.max(0, v.length - 4)) + v.slice(-4) : ''); const keys = (s?.keys) || {}; const masked = {}; for (const k of Object.keys(keys)) masked[k] = mask(keys[k]); return json({ keys: masked, alerts: s?.alerts || { slack: '', discord: '', telegram: '', email: '', notifyOn: 'high' }, hasKeys: Object.keys(keys).length > 0 }); }
      if (method === 'POST') { const b = await request.json(); const existing = await col.findOne({ id: 'global' }); const keys = { ...(existing?.keys || {}) }; if (b.keys) for (const k of Object.keys(b.keys)) { if (b.keys[k] && !/^•/.test(b.keys[k])) keys[k] = b.keys[k]; } await col.updateOne({ id: 'global' }, { $set: { id: 'global', keys, alerts: b.alerts || existing?.alerts || {}, updatedAt: new Date().toISOString() } }, { upsert: true }); return json({ saved: true }); }
    }

    // ---- SCHEDULES ----
    if (p0 === 'schedules') {
      const col = db.collection('schedules');
      if (method === 'GET') { const items = await col.find({}, { projection: { _id: 0 } }).sort({ createdAt: -1 }).toArray(); return json(items); }
      if (method === 'POST') { const b = await request.json(); const doc = { id: uuidv4(), assetId: b.assetId || null, assetName: b.assetName || 'All assets', frequency: b.frequency || 'daily', time: b.time || '02:00', enabled: b.enabled !== false, channels: b.channels || [], createdAt: new Date().toISOString() }; await col.insertOne(doc); const { _id, ...clean } = doc; return json(clean, 201); }
      if (method === 'DELETE' && p1) { await col.deleteOne({ id: p1 }); return json({ deleted: true }); }
    }

    return json({ error: 'route not found', path: segs, method }, 404);
  } catch (e) {
    return json({ error: e.message, stack: process.env.NODE_ENV === 'development' ? e.stack : undefined }, 500);
  }
}

export async function GET(request, ctx) { return handle(request, ctx, 'GET'); }
export async function POST(request, ctx) { return handle(request, ctx, 'POST'); }
export async function PATCH(request, ctx) { return handle(request, ctx, 'PATCH'); }
export async function DELETE(request, ctx) { return handle(request, ctx, 'DELETE'); }
export async function OPTIONS() { return new NextResponse(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } }); }

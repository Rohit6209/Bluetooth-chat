// MeshChat server: relays END-TO-END ENCRYPTED envelopes only (server never sees plaintext).
const express = require('express'), http = require('http'), crypto = require('crypto'), { Server } = require('socket.io');
const app = express(), srv = http.createServer(app), io = new Server(srv);
const ADMIN_USER = process.env.ADMIN_USER || 'admin', ADMIN_PASS = process.env.ADMIN_PASSWORD || 'admin123';
if (!process.env.ADMIN_PASSWORD) console.warn('⚠️  ADMIN_PASSWORD set nahi hai, default "admin123" chal raha hai. Deploy se pehle badlo!');

const users = new Map();   // name -> { p, pub, sid, ip, ua, since, lastSeen, sent, recv }
const queue = new Map();   // name -> [envelope]   (store-and-forward for offline users)
const notices = new Map(); // name -> [{id,to,state}] delivery receipts for offline senders
const events = [], stats = { relayed: 0, started: Date.now() };
const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
const ev = (type, text) => { events.unshift({ t: Date.now(), type, text }); if (events.length > 100) events.pop(); };
const sock = n => { const u = users.get(n); return u && u.sid && io.sockets.sockets.get(u.sid); };
const broadcast = () => io.emit('users', [...users].map(([name]) => ({ name, on: !!sock(name) })));
const device = ua => {
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Mac OS/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : '?';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox/.test(ua) ? 'Firefox' : /Chrome/.test(ua) ? 'Chrome' : /Safari/.test(ua) ? 'Safari' : '?';
  return os + ' • ' + br;
};

// ---------- Admin (Basic Auth) ----------
const hash = s => crypto.createHash('sha256').update(String(s)).digest();
function adminAuth(req, res, next) {
  const [t, v] = (req.headers.authorization || '').split(' ');
  const [u, ...p] = Buffer.from(v || '', 'base64').toString().split(':');
  if (t === 'Basic' && crypto.timingSafeEqual(hash(u), hash(ADMIN_USER)) && crypto.timingSafeEqual(hash(p.join(':')), hash(ADMIN_PASS))) return next();
  res.set('WWW-Authenticate', 'Basic realm="MeshChat Admin"').status(401).send('Login required');
}
app.use('/admin', adminAuth);
app.get('/admin/api/stats', (req, res) => {
  const list = [...users].map(([name, u]) => ({
    name, online: !!sock(name), ip: u.ip, device: u.device, since: u.since, lastSeen: u.lastSeen,
    sent: u.sent, recv: u.recv, queued: (queue.get(name) || []).length
  }));
  res.json({
    registered: list.length, online: list.filter(u => u.online).length, relayed: stats.relayed,
    queued: list.reduce((a, u) => a + u.queued, 0), uptime: Date.now() - stats.started, users: list, events, now: Date.now()
  });
});
app.post('/admin/api/kick/:name', (req, res) => {
  const s = sock(req.params.name); if (!s) return res.status(404).json({ ok: false });
  s.disconnect(true); ev('kick', req.params.name + ' ko admin ne disconnect kiya'); res.json({ ok: true });
});
app.use('/admin', express.static('admin'));
app.use(express.static('public'));

// ---------- Chat ----------
function notify(from, id, to, state) {
  const s = sock(from), n = { id, to, state };
  s ? s.emit('status', n) : push(notices, from, n);
}
function deliver(env) {
  const t = sock(env.to);
  if (!t) { ev('queue', `${env.from} → ${env.to} (offline, queue me)`); return push(queue, env.to, env); }
  t.timeout(8000).emit('msg', env, err => {
    if (err) return push(queue, env.to, env);
    const r = users.get(env.to); if (r) r.recv++;
    ev('msg', `${env.from} → ${env.to} delivered (hops: ${env.hops.join('→')})`);
    notify(env.from, env.id, env.to, 'delivered');
  });
}

io.on('connection', s => {
  s.on('join', ({ name, pub } = {}, ack) => {
    name = String(name || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
    if (!name || !pub) return ack({ ok: false, err: 'Naam galat hai (a-z, 0-9, _ )' });
    const u = users.get(name), p = JSON.stringify(pub);
    if (u && u.p !== p) return ack({ ok: false, err: 'Ye naam kisi aur ka hai' });
    const hs = s.handshake, ip = String(hs.headers['x-forwarded-for'] || hs.address || '').split(',')[0].trim();
    users.set(name, { p, pub, sid: s.id, ip, device: device(hs.headers['user-agent'] || ''), since: Date.now(), lastSeen: Date.now(), sent: u ? u.sent : 0, recv: u ? u.recv : 0 });
    s.data.name = name; ack({ ok: true }); broadcast(); ev('join', `${name} connect hua (${ip})`);
    (notices.get(name) || []).forEach(n => s.emit('status', n)); notices.delete(name);
    const q = queue.get(name) || []; queue.delete(name); q.forEach(deliver);
  });
  s.on('getkey', (n, ack) => ack((users.get(n) || {}).pub || null));
  s.on('send', (m, ack) => {
    const from = s.data.name;
    if (!from || !m || !users.has(m.to) || typeof m.id !== 'string' || !m.pl) return ack({ state: 'failed' });
    const me = users.get(from); me.sent++; me.lastSeen = Date.now(); stats.relayed++;
    deliver({ id: m.id.slice(0, 16), from, to: m.to, ttl: m.ttl, hops: [...(m.hops || []), 'server'], ts: m.ts, pl: m.pl });
    ack({ state: 'sent' });
  });
  s.on('disconnect', () => {
    const n = s.data.name, u = n && users.get(n);
    if (u && u.sid === s.id) { u.sid = null; u.lastSeen = Date.now(); broadcast(); ev('leave', `${n} disconnect hua`); }
  });
});

srv.listen(process.env.PORT || 3000, () => console.log('MeshChat running on port ' + (process.env.PORT || 3000)));

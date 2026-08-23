require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const fetch = require('node-fetch');
const FormData = require('form-data');
const crypto = require('crypto');
const Stripe = require('stripe');
const bcryptjs = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);

// Trust Railway's proxy so req.protocol reports https correctly
app.set('trust proxy', 1);

// POSTGRES DATABASE CONNECTION
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database schema
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        stripe_customer_id TEXT,
        subscription_status TEXT DEFAULT 'inactive',
        subscription_id TEXT,
        trial_end INTEGER,
        created_at INTEGER DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        token TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER
      )
    `);

    console.log('Database tables initialized');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}

initializeDatabase();

// MIDDLEWARE
const jsonParser = express.json({ limit: '50mb' });
app.use((req, res, next) => {
  if (req.originalUrl === '/api/webhook') return next();
  jsonParser(req, res, next);
});
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new PgSession({ pool: pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'ftf-secret-change-me',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// AUTH MIDDLEWARE
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

async function requireSubscription(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  try {
    const result = await pool.query('SELECT subscription_status, trial_end FROM users WHERE id = $1', [req.session.userId]);
    if (result.rows.length === 0) return res.redirect('/login');
    const u = result.rows[0];
    const now = Math.floor(Date.now() / 1000);
    const isActive = u.subscription_status === 'active';
    const trialValid = u.trial_end && u.trial_end > now;
    if (!isActive && !trialValid) return res.redirect('/subscribe');
    req.user = {
      id: req.session.userId,
      subscription_status: u.subscription_status,
      trial_end: u.trial_end
    };
    next();
  } catch (err) {
    console.error('Subscription check error:', err);
    return res.redirect('/login');
  }
}

// PAGES
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.get('/subscribe', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subscribe.html'));
});

app.get('/app', requireSubscription, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.get('/account', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'account.html'));
});

app.get('/success', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'success.html'));
});

// AUTH ROUTES
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'An account with this email already exists' });

    const hashed = await bcryptjs.hash(password, 10);

    const customer = await stripe.customers.create({ email: email.toLowerCase() });

    const trialEnd = Math.floor(Date.now() / 1000) + (14 * 24 * 60 * 60);

    const result = await pool.query(
      'INSERT INTO users (email, password, stripe_customer_id, subscription_status, trial_end) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [email.toLowerCase(), hashed, customer.id, 'trialing', trialEnd]
    );

    req.session.userId = result.rows[0].id;
    res.json({ success: true, redirect: '/app' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcryptjs.compare(password, user.rows[0].password);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const now = Math.floor(Date.now() / 1000);
    const isTrialing = user.rows[0].trial_end && user.rows[0].trial_end > now;
    const isActive = user.rows[0].subscription_status === 'active';
    if (!isTrialing && !isActive) return res.redirect('/login');
    
    req.session.userId = user.rows[0].id;
    res.json({ success: true, redirect: '/app' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// PASSWORD RESET ROUTES
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    
    if (user.rows.length === 0) {
      return res.json({ success: true, message: 'If an account exists, a reset link has been sent' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Math.floor(Date.now() / 1000) + (60 * 60);

    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.rows[0].id, token, expiresAt]
    );

    const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${token}`;
    
    await resend.emails.send({
      from: 'noreply@frame-to-form.com',
      to: email.toLowerCase(),
      subject: 'Reset your Frame to Form password',
      html: `
        <h2>Password Reset Request</h2>
        <p>Click the link below to reset your password. This link expires in 1 hour.</p>
        <a href="${resetLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        <p>Or copy this link: ${resetLink}</p>
        <p>If you didn't request this, you can ignore this email.</p>
      `
    });

    res.json({ success: true, message: 'If an account exists, a reset link has been sent' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  try {
    const now = Math.floor(Date.now() / 1000);
    
    const resetToken = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = $1 AND expires_at > $2',
      [token, now]
    );

    if (resetToken.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset link' });
    }

    const userId = resetToken.rows[0].user_id;
    const hashed = await bcryptjs.hash(password, 10);

    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, userId]);

    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]);

    res.json({ success: true, message: 'Password reset successfully', redirect: '/login' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// STRIPE ROUTES
app.post('/api/create-checkout', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const baseUrl = `${req.protocol}://${req.get('host')}`;

    const session = await stripe.checkout.sessions.create({
      customer: user.rows[0].stripe_customer_id,
      payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/subscribe`
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/user', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT subscription_status, trial_end FROM users WHERE id = $1', [req.session.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const now = Math.floor(Date.now() / 1000);
    const daysLeft = user.rows[0].trial_end ? Math.ceil((user.rows[0].trial_end - now) / 86400) : 0;
    res.json({
      subscription_status: user.rows[0].subscription_status,
      trial_end: user.rows[0].trial_end,
      trial_days_left: daysLeft
    });
  } catch (err) {
    console.error('User fetch error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/customer-portal', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT stripe_customer_id FROM users WHERE id = $1', [req.session.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: user.rows[0].stripe_customer_id,
      return_url: `${req.protocol}://${req.get('host')}/account`
    });
    res.json({ url: portalSession.url });
  } catch (err) {
    console.error('Portal error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Stripe webhook
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'customer.subscription.updated':
    case 'customer.subscription.created': {
      const sub = event.data.object;
      await pool.query('UPDATE users SET subscription_status = $1, subscription_id = $2 WHERE stripe_customer_id = $3', [sub.status, sub.id, sub.customer]);
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      await pool.query('UPDATE users SET subscription_status = $1 WHERE stripe_customer_id = $2', ['cancelled', sub.customer]);
      break;
    }
  }

  res.json({ received: true });
});

// PIPELINE ROUTES

// Remove.bg proxy
app.post('/api/remove-bg', requireSubscription, upload.single('image'), async (req, res) => {
  try {
    const apikey = req.headers['x-removebg-key'];
    if (!apikey) return res.status(400).json({ error: 'Missing Remove.bg API key' });
    if (!req.file) return res.status(400).json({ error: 'No image provided' });

    const fd = new FormData();
    fd.append('image_file', req.file.buffer, { filename: req.file.originalname || 'image.png', contentType: req.file.mimetype });

    const r = await fetch('https://api.remove.bg/v1.0/removebg', { method: 'POST', headers: { 'X-Api-Key': apikey }, body: fd });
    if (!r.ok) {
      const err = await r.json();
      return res.status(r.status).json({ error: err.message || 'Remove.bg error' });
    }

    const buf = await r.buffer();
    res.set('Content-Type', 'image/png');
    res.send(buf);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Flux image generation
app.post('/api/generate-image', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    const { prompt, index, subjectType } = req.body;
    const seeds = [42, 154, 286, 512, 999, 1337, 2048, 7777, 33337, 65535];
    const fullPrompt = subjectType === 'people'
      ? prompt + '. full body shot, entire figure visible head to toe, legs and feet fully visible, standing on ground, no crop, wide shot'
      : prompt;
    const imageSizes = [832, 896];
    const seed = seeds[index % seeds.length];
    const imageSize = imageSizes[index % imageSizes.length];

    const r = await fetch('https://fal.run/fal-ai/flux-2-pro', {
      method: 'POST',
      headers: { 'Authorization': 'Key ' + falkey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: fullPrompt, image_size: { width: imageSize, height: imageSize }, seed })
    });

    if (!r.ok) {
      let err = {};
      try { err = await r.json(); } catch (parseErr) {}
      let detail = err.message || err.detail || 'Flux API error';
      if (Array.isArray(detail)) detail = detail.map(function(d) { return d.msg || JSON.stringify(d); }).join('; ');
      else if (typeof detail === 'object') detail = JSON.stringify(detail);
      return res.status(r.status).json({ error: detail });
    }

    const data = await r.json();
    if (!data.images || data.images[0] === undefined) {
      let detail = 'No image returned from Flux';
      if (data.detail) {
        detail = Array.isArray(data.detail) ? data.detail.map(d => d.msg).join(', ') : data.detail;
      }
      console.error('Flux API error [' + r.status + ']:', JSON.stringify(data));
      return res.status(500).json({ error: 'Flux - ' + detail });
    }

    const imageUrl = data.images[0].url;
    if (!imageUrl) return res.status(500).json({ error: 'No image URL from Flux' });
    res.json({ image_url: imageUrl });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Trellis submit
app.post('/api/trellis/submit', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    const { image_url, image_base64 } = req.body;
    if (!image_url && !image_base64) return res.status(400).json({ error: 'No image provided' });

    let finalUrl = image_url;

    if (!finalUrl) {
      const imageBase64 = image_base64.match(/data:[^;]*;base64,(.+)/)?.[1];
      const buffer = Buffer.from(imageBase64, 'base64');
      const filename = 'figure_' + Date.now() + '.png';
      const initData = await fetch('https://rest.alpha.fal.ai/storage/upload/initiate?storage_type=fal-cdn-v3', {
        method: 'POST',
        headers: { 'Authorization': 'Key ' + falkey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_name: filename, content_type: 'image/png' })
      });
      if (!initData.ok) throw new Error('CDN initiate failed: ' + initData.status);
      const initBody = await initData.json();
      const uploadUrl = initBody.upload_url;
      if (!uploadUrl) throw new Error('No upload_url from CDN');
      const putResp = await fetch(uploadUrl, { method: 'PUT', headers: { 'Content-Type': 'image/png' }, body: buffer });
      if (!putResp.ok) throw new Error('CDN PUT failed: ' + putResp.status);
      finalUrl = initBody.file_url;
    }

    const submit = await fetch('https://queue.fal.run/fal-ai/trellis-2', {
      method: 'POST',
      headers: { 'Authorization': 'Key ' + falkey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_url: finalUrl })
    });
    if (!submit.ok) {
      const data = await submit.json();
      return res.status(submit.status).json({ error: data.message || data.detail || 'Trellis error' });
    }
    const requestData = await submit.json();
    const requestId = requestData.request_id;
    if (!requestId) return res.status(500).json({ error: 'No request_id from Trellis' });
    res.json({ task_id: requestId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Hunyuan submit
// Hunyuan submit
app.post('/api/hunyuan/submit', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    const { image_url } = req.body;
    if (!image_url) return res.status(400).json({ error: 'Missing image_url' });

    const result = await fetch('https://queue.fal.run/fal-ai/hunyuan-3d/v3.1/pro/image-to-3d', {
      method: 'POST',
      headers: { 'Authorization': 'Key ' + falkey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_url })
    });
    const data = await result.json();
    return res.json({ task_id: data.request_id || data.id });
  } catch (e) { 
    res.status(500).json({ error: e.message }); 
  }
});
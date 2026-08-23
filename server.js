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
    const subscription = await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: process.env.STRIPE_PRICE_ID }],
      trial_end: trialEnd
    });

    const result = await pool.query(
      'INSERT INTO users (email, password, stripe_customer_id, subscription_status, subscription_id, trial_end) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [email.toLowerCase(), hashed, customer.id, 'trialing', subscription.id, trialEnd]
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
      html: `<h2>Password Reset Request</h2><p>Click the link below to reset your password. This link expires in 1 hour.</p><a href="${resetLink}">Reset Password</a>`
    });

    res.json({ success: true, message: 'Reset link sent to your email' });
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
    const resetToken = await pool.query('SELECT * FROM password_reset_tokens WHERE token = $1', [token]);
    if (resetToken.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired token' });
    
    const now = Math.floor(Date.now() / 1000);
    if (resetToken.rows[0].expires_at < now) return res.status(400).json({ error: 'Token has expired' });

    const userId = resetToken.rows[0].user_id;
    const hashed = await bcryptjs.hash(password, 10);

    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, userId]);
    await pool.query('DELETE FROM password_reset_tokens WHERE token = $1', [token]);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// FLUX IMAGE GENERATION
app.post('/api/flux/generate', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    const prompt = req.body.prompt;
    const numImages = parseInt(req.body.numImages) || 1;
    const subjectType = req.body.subjectType || 'object';
    
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    if (!prompt) return res.status(400).json({ error: 'Prompt required' });

    const urls = [];
    for (let i = 0; i < numImages; i++) {
      const submit = await fetch('https://queue.fal.run/fal-ai/flux-2-pro/requests/submit/text-to-image', {
        method: 'POST',
        headers: { 'Authorization': 'Key ' + falkey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: prompt })
      });
      if (!submit.ok) {
        const data = await submit.json();
        return res.status(submit.status).json({ error: data.message || data.detail || 'FLUX error' });
      }
      const requestData = await submit.json();
      const requestId = requestData.request_id;
      if (!requestId) return res.status(500).json({ error: 'No request_id from FLUX' });

      let done = false;
      let attempts = 0;
      while (!done && attempts < 300) {
        const status = await fetch('https://queue.fal.run/fal-ai/flux-2-pro/requests/' + requestId + '/status', {
          headers: { 'Authorization': 'Key ' + falkey }
        });
        const statusData = await status.json();
        const statusValue = statusData.status || statusData.state || '';

        if (statusValue === 'COMPLETED') {
          const result = await fetch('https://queue.fal.run/fal-ai/flux-2-pro/requests/' + requestId, {
            headers: { 'Authorization': 'Key ' + falkey }
          });
          const resultData = await result.json();
          const url = resultData.images?.[0]?.url || resultData.output?.images?.[0]?.url || resultData.output?.url;
          if (url) urls.push(url);
          done = true;
        } else if (statusValue === 'FAILED') {
          return res.status(500).json({ error: 'FLUX generation failed' });
        }
        if (!done) {
          attempts++;
          await new Promise(resolve => setTimeout(resolve, 500));
        }
      }
    }
    res.json({ images: urls });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// REMOVE.BG
app.post('/api/remove-bg', requireSubscription, async (req, res) => {
  try {
    const rbgkey = req.headers['x-removebg-key'];
    if (!rbgkey) return res.status(400).json({ error: 'Missing Remove.bg key' });
    if (!req.file && !req.body.image) return res.status(400).json({ error: 'No image' });

    const imageBuffer = req.file ? req.file.buffer : Buffer.from(req.body.image, 'base64');
    const fd = new FormData();
    fd.append('image_file', imageBuffer, 'image.png');

    const response = await fetch('https://api.remove.bg/v1.0/removebg', {
      method: 'POST',
      headers: { 'X-API-Key': rbgkey },
      body: fd
    });

    if (!response.ok) {
      const data = await response.json();
      return res.status(response.status).json({ error: data.errors?.[0]?.title || 'Remove.bg failed' });
    }

    const buffer = await response.buffer();
    res.set('Content-Type', 'image/png');
    res.send(buffer);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// TRELLIS-2 SUBMIT
app.post('/api/trellis/submit', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    
    let body;
    if (req.body.image_base64) {
      body = { image: { data: req.body.image_base64 } };
    } else if (req.body.image_url) {
      body = { image_url: req.body.image_url };
    } else {
      return res.status(400).json({ error: 'No image provided' });
    }

    const submit = await fetch('https://queue.fal.run/fal-ai/trellis-2/requests/submit/image-to-3d', {
      method: 'POST',
      headers: { 'Authorization': 'Key ' + falkey, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
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

// Trellis poll
app.get('/api/trellis/status/:taskId', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    const taskId = req.params.taskId;

    const status = await fetch('https://queue.fal.run/fal-ai/trellis-2/requests/' + taskId + '/status', {
      headers: { 'Authorization': 'Key ' + falkey }
    });
    const statusData = await status.json();
    const statusValue = statusData.status || statusData.state || '';

    if (statusValue === 'COMPLETED') {
      const result = await fetch('https://queue.fal.run/fal-ai/trellis-2/requests/' + taskId, {
        headers: { 'Authorization': 'Key ' + falkey }
      });
      const resultData = await result.json();
      const url = resultData.model_glb?.url || resultData.output?.model_glb?.url || resultData.model_mesh?.url || resultData.output?.model_mesh?.url || resultData.model_glb_url || resultData.output?.model_glb_url || resultData.data?.model_glb_url;
      return res.json({ status: 'FINISHED', result_url: url });
    }
    if (statusValue === 'FAILED' || statusValue === 'ERROR') return res.json({ status: 'FAILED', error: statusData.error || 'Failed' });
    res.json({ status: 'PROCESSING' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// HUNYUAN3D SUBMIT (NEW)
app.post('/api/hunyuan/submit', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    
    let body;
    if (req.body.image_base64) {
      body = { image: { data: req.body.image_base64 } };
    } else if (req.body.image_url) {
      body = { image_url: req.body.image_url };
    } else {
      return res.status(400).json({ error: 'No image provided' });
    }

    const submit = await fetch('https://queue.fal.run/fal-ai/hunyuan-3d/v3.1/pro/image-to-3d/requests/submit/image-to-3d', {
      method: 'POST',
      headers: { 'Authorization': 'Key ' + falkey, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!submit.ok) {
      const data = await submit.json();
      return res.status(submit.status).json({ error: data.message || data.detail || 'Hunyuan error' });
    }
    const requestData = await submit.json();
    const requestId = requestData.request_id;
    if (!requestId) return res.status(500).json({ error: 'No request_id from Hunyuan' });
    res.json({ task_id: requestId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Hunyuan poll (FIXED)
app.get('/api/hunyuan/status/:taskId', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    const taskId = req.params.taskId;

    const status = await fetch('https://queue.fal.run/fal-ai/hunyuan-3d/v3.1/pro/image-to-3d/requests/' + taskId + '/status', {
      headers: { 'Authorization': 'Key ' + falkey }
    });
    const statusData = await status.json();
    const statusValue = statusData.status || statusData.state || '';

    if (statusValue === 'COMPLETED') {
      const result = await fetch('https://queue.fal.run/fal-ai/hunyuan-3d/v3.1/pro/image-to-3d/requests/' + taskId, {
        headers: { 'Authorization': 'Key ' + falkey }
      });
      const resultData = await result.json();
      const url = resultData.model_glb?.url || resultData.output?.model_glb?.url || resultData.model_mesh?.url || resultData.output?.model_mesh?.url || resultData.output?.model_glb_url || resultData.output?.model_gltf_url || resultData.data?.model_glb_url;
      return res.json({ status: 'FINISHED', result_url: url });
    }
    if (statusValue === 'FAILED' || statusValue === 'ERROR') {
      return res.json({ status: 'FAILED', error: statusData.error || 'Failed' });
    }
    // For PENDING, PROCESSING, or any other status - ALWAYS return a response
    return res.json({ status: 'PROCESSING' });
  } catch (e) { 
    return res.status(500).json({ error: e.message }); 
  }
});

// Trellis poll (FIXED - same pattern)
app.get('/api/trellis/status/:taskId', requireSubscription, async (req, res) => {
  try {
    const falkey = req.headers['x-fal-key'];
    if (!falkey) return res.status(400).json({ error: 'Missing fal.ai key' });
    const taskId = req.params.taskId;

    const status = await fetch('https://queue.fal.run/fal-ai/trellis/requests/' + taskId + '/status', {
      headers: { 'Authorization': 'Key ' + falkey }
    });
    const statusData = await status.json();
    const statusValue = statusData.status || '';

    if (statusValue === 'COMPLETED') {
      const result = await fetch('https://queue.fal.run/fal-ai/trellis/requests/' + taskId, {
        headers: { 'Authorization': 'Key ' + falkey }
      });
      const resultData = await result.json();
      const url = resultData.model_glb?.url || resultData.output?.model_glb?.url || resultData.data?.glb?.url;
      return res.json({ status: 'FINISHED', result_url: url });
    }
    if (statusValue === 'FAILED') {
      return res.json({ status: 'FAILED', error: statusData.error || 'Failed' });
    }
    // For PENDING, PROCESSING, or any other status - ALWAYS return a response
    return res.json({ status: 'PROCESSING' });
  } catch (e) { 
    return res.status(500).json({ error: e.message }); 
  }
});

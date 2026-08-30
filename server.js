import express from 'express';
import pg from 'pg';
import Stripe from 'stripe';
import axios from 'axios';
import { fal } from '@fal-ai/client';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(express.json());
app.use(express.static('public'));

async function requireSubscription(req, res, next) {
  const email = req.headers['x-email'];
  if (!email) return res.status(401).json({ error: 'Missing email' });
  const user = await db.query('SELECT subscription_status FROM users WHERE email = $1', [email]);
  if (!user.rows.length || user.rows[0].subscription_status !== 'active') {
    return res.status(403).json({ error: 'Subscription required' });
  }
  next();
}

async function initDB() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        stripe_customer_id VARCHAR(255),
        subscription_status VARCHAR(50) DEFAULT 'free',
        created_at BIGINT
      )
    `);
    await db.query(`
      CREATE TABLE IF NOT EXISTS conversions (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        model VARCHAR(255),
        image_url TEXT,
        result_url TEXT,
        status VARCHAR(50),
        created_at BIGINT
      )
    `);
    console.log('Database initialized');
  } catch (err) {
    console.error('DB init error:', err.message);
  }
}

app.post('/api/generate-image', async (req, res) => {
  try {
    const { prompt, index } = req.body;
    const falKey = req.headers['x-fal-key'];
    if (!falKey) return res.status(400).json({ error: 'Missing fal.ai key' });
    if (!prompt) return res.status(400).json({ error: 'Missing prompt' });
    const result = await axios.post('https://queue.fal.run/fal-ai/flux-2-pro', {
      prompt,
      image_size: 'square_hd'
    }, {
      headers: { 'Authorization': 'Key ' + falKey }
    });
    const data = result.data;
    return res.json({
      index,
      image_url: data.images?.[0]?.url || null,
      request_id: data.request_id
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/remove-bg', async (req, res) => {
  try {
    const { image_url } = req.body;
    if (!image_url) return res.status(400).json({ error: 'Missing image_url' });
    const response = await axios.post('https://api.remove.bg/v1.0/removebg', 
      { image_url, type: 'auto', format: 'PNG' },
      { headers: { 'X-Api-Key': process.env.REMOVE_BG_API_KEY } }
    );
    const base64 = response.data.toString('base64');
    res.json({ image: 'data:image/png;base64,' + base64 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/convert-3d', async (req, res) => {
  try {
    const { image_url, model } = req.body;
    const falKey = req.headers['x-fal-key'];
    if (!falKey) return res.status(400).json({ error: 'Missing fal.ai key' });
    if (!image_url) return res.status(400).json({ error: 'Missing image_url' });
    if (!model) return res.status(400).json({ error: 'Missing model' });

    fal.config({ credentials: falKey });

    const input = {};
    if (model.includes('hunyuan')) {
      input.input_image_url = image_url;
    } else {
      input.image_url = image_url;
    }

    const result = await fal.subscribe(model, { input });

    let glbUrl = null;
    if (model.includes('hunyuan')) {
      glbUrl = result.data?.glb?.url;
    } else {
      glbUrl = result.data?.model_glb?.url;
    }

    if (!glbUrl) {
      return res.status(500).json({ error: 'No GLB URL in response', data: result.data });
    }

    res.json({
      status: 'COMPLETED',
      result_url: glbUrl,
      model: model
    });

  } catch (error) {
    console.error('F2F 2.0 Conversion error:', error.message);
    res.status(500).json({ 
      error: error.message || 'Conversion failed',
      details: error.body?.detail || null
    });
  }
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    if (event.type === 'charge.succeeded') {
      const email = event.data.object.metadata?.email;
      if (email) {
        await db.query(
          'INSERT INTO users (email, subscription_status, created_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET subscription_status = $2',
          [email, 'active', Math.floor(Date.now() / 1000)]
        );
      }
    }
    res.json({ received: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/stats', async (req, res) => {
  try {
    const recentSignups = await db.query(
      'SELECT email, created_at, subscription_status FROM users ORDER BY created_at DESC LIMIT 50'
    );
    const html = '<html><head><title>F2F 2.0 Stats</title><style>body{font-family:sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:12px;text-align:left}th{background-color:#4CAF50;color:white}</style></head><body><h1>Frame to Form 2.0</h1><table><tr><th>Email</th><th>Signed Up</th><th>Status</th></tr>' + recentSignups.rows.map(user => '<tr><td>' + user.email + '</td><td>' + new Date(user.created_at * 1000).toLocaleDateString() + '</td><td>' + user.subscription_status + '</td></tr>').join('') + '</table></body></html>';
    res.send(html);
  } catch (err) {
    res.status(500).send('Error loading stats');
  }
});

async function start() {
  await initDB();
  app.listen(PORT, () => {
    console.log('\n FRAME TO FORM 2.0 | fal.ai SDK Integration | http://localhost:' + PORT + ' \n');
  });
}

start();
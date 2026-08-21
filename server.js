require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;

// ── Required environment variables ──────────────────────────────────
// DATABASE_URL   → Render Postgres connection string
// JWT_SECRET     → any long random string, used to sign session tokens
if (!process.env.JWT_SECRET) {
  console.error('❌ Missing JWT_SECRET env var. Sessions cannot be signed safely without it. Refusing to start.');
  process.exit(1);
}

app.use(express.json());
app.use(cors({ origin: '*', credentials: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.stack);
  } else {
    console.log('⚡ Connected to Render PostgreSQL successfully!');
    release();
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: "Zero'O Clock Real-time API Active" });
});

// ── Auth middleware ──────────────────────────────────────────────────
// Verifies the JWT on protected routes and attaches the decoded payload
// ({ id, username, role }) to req.user. Nothing downstream trusts a role
// claimed by the client itself — it always comes from this verified token.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No session token provided.' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function publicProfile(row) {
  // Never send password_hash, and never send email/instagram to anyone
  // but the owner — the same "hide personal handles" rule from the app.
  const { password_hash, email, ...rest } = row;
  return rest;
}

// ==========================================
// AUTHENTICATION
// ==========================================

app.post('/api/register', async (req, res) => {
  try {
    const { nickname, username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Please fill in all required fields.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    const cleanUsername = username.trim().replace(/^@/, '');
    const cleanEmail = email.trim().toLowerCase();

    const existing = await pool.query(
      'SELECT id FROM profiles WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)',
      [cleanUsername, cleanEmail]
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username or Email is already registered!' });
    }

    // Real hashing — this is the fix for the earlier version, which stored
    // the raw password directly despite the column being called password_hash.
    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO profiles (nickname, username, email, password_hash, role, current_hp, total_hp, streak_count, created_at)
       VALUES ($1, $2, $3, $4, 'member', 0, 0, 0, NOW())
       RETURNING id, nickname, username, email, role, current_hp, total_hp, streak_count, created_at`,
      [nickname || cleanUsername, cleanUsername, cleanEmail, passwordHash]
    );

    const user = result.rows[0];
    const token = signToken(user);
    res.status(201).json({ success: true, token, user: publicProfile(user) });
  } catch (err) {
    console.error('Registration Error:', err);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body; // username OR email
    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username/Gmail and Password are required.' });
    }

    const cleanIdentifier = identifier.trim().replace(/^@/, '').toLowerCase();
    const result = await pool.query(
      'SELECT * FROM profiles WHERE LOWER(email) = $1 OR LOWER(username) = $1',
      [cleanIdentifier]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Member not found. Please check your Username or Gmail.' });
    }

    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Incorrect password. Please try again.' });
    }

    const token = signToken(user);
    res.json({ success: true, token, user: publicProfile(user) });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM profiles WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Profile not found.' });
    // /api/me is the one place the owner gets their own email back too.
    const { password_hash, ...own } = result.rows[0];
    res.json(own);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching your profile.' });
  }
});

// ==========================================
// COMMUNITY (real members only — no mock fallback data)
// ==========================================

app.get('/api/community/members', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, nickname, username, current_hp, total_hp, streak_count
       FROM profiles ORDER BY total_hp DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching community members.' });
  }
});

app.get('/api/profiles/:username', requireAuth, async (req, res) => {
  try {
    const cleanUsername = req.params.username.replace(/^@/, '');
    const result = await pool.query(
      'SELECT id, nickname, username, current_hp, total_hp, streak_count FROM profiles WHERE LOWER(username) = LOWER($1)',
      [cleanUsername]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Profile not found.' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching profile.' });
  }
});

// ==========================================
// STREAMING / SCROBBLES
// ==========================================

const HP_PER_STREAM = 2;

app.post('/api/scrobble', requireAuth, async (req, res) => {
  try {
    const { track, artist, platform } = req.body;
    if (!track || !platform) return res.status(400).json({ error: 'track and platform are required.' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const log = await client.query(
        `INSERT INTO stream_logs (user_id, track, artist, platform, created_at)
         VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
        [req.user.id, track, artist || null, platform]
      );
      const updated = await client.query(
        `UPDATE profiles SET current_hp = current_hp + $1, total_hp = total_hp + $1
         WHERE id = $2 RETURNING id, current_hp, total_hp`,
        [HP_PER_STREAM, req.user.id]
      );
      await client.query('COMMIT');
      res.status(201).json({ success: true, log: log.rows[0], profile: updated.rows[0] });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Scrobble Error:', err);
    res.status(500).json({ error: 'Server error logging stream.' });
  }
});

app.get('/api/streams/recent', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sl.track, sl.artist, sl.platform, sl.created_at, p.username, p.nickname
       FROM stream_logs sl JOIN profiles p ON p.id = sl.user_id
       ORDER BY sl.created_at DESC LIMIT 30`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching recent streams.' });
  }
});

// ==========================================
// SUPPORT TICKETS
// ==========================================

app.post('/api/support', requireAuth, async (req, res) => {
  try {
    const { type, details, preferred_platform, contact_handle } = req.body;
    const result = await pool.query(
      `INSERT INTO support_tickets (user_id, username, type, details, preferred_platform, contact_handle, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', NOW()) RETURNING *`,
      [req.user.id, req.user.username, type || 'HELP', details, preferred_platform, contact_handle]
    );
    res.status(201).json({ success: true, ticket: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error submitting ticket.' });
  }
});

// ==========================================
// ADMIN (all require a verified admin-role token — never a client-claimed role)
// ==========================================

app.get('/api/admin/support', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM support_tickets ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching support tickets.' });
  }
});

app.patch('/api/admin/support/:id/resolve', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE support_tickets SET status = 'RESOLVED' WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    res.json({ success: true, ticket: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error resolving ticket.' });
  }
});

app.get('/api/admin/members', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, nickname, username, email, current_hp, total_hp, streak_count, role, created_at
       FROM profiles ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching members.' });
  }
});

app.delete('/api/admin/members/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (String(req.params.id) === String(req.user.id)) {
      return res.status(400).json({ error: "You can't delete your own admin account from here." });
    }
    const result = await pool.query('DELETE FROM profiles WHERE id = $1 RETURNING id', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Member not found.' });
    res.json({ success: true, deletedId: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Server error deleting member.' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Zero'O Clock backend running on port ${PORT}`);
});
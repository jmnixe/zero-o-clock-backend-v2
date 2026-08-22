require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;

// Render terminates HTTPS and forwards requests to this app over plain
// HTTP internally. Without this, req.protocol always reports 'http' even
// on a real https:// connection, which made every generated scrobble URL
// (webhook + ListenBrainz API URL) come out wrong. This tells Express to
// trust Render's X-Forwarded-Proto header instead of guessing.
app.set('trust proxy', 1);

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

// Every 10 completed streams earns 1 HP — not per-stream. Deduplication
// window protects against a client (webhook retry, flaky connection,
// duplicate delivery) sending the exact same track twice in a row and
// inflating the count. This is the ONE place stream-logging happens —
// the simulate button, the Web Scrobbler webhook, and the
// ListenBrainz-compatible endpoint all call this same function, so
// behavior can't quietly diverge between them.
const STREAMS_PER_HP = 10;
const DEDUPE_WINDOW_SECONDS = 120;

async function logStreamForUser(userId, { track, artist, platform }) {
  if (!track || !platform) return { error: 'track and platform are required.' };

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Deduplicate: same user + same track + same artist within the window
    // is treated as a duplicate delivery, not a second stream.
    const dupe = await client.query(
      `SELECT id FROM stream_logs
       WHERE user_id = $1 AND track = $2 AND COALESCE(artist, '') = COALESCE($3, '')
         AND created_at > NOW() - INTERVAL '${DEDUPE_WINDOW_SECONDS} seconds'
       LIMIT 1`,
      [userId, track, artist || null]
    );
    if (dupe.rows.length > 0) {
      await client.query('ROLLBACK');
      return { duplicate: true };
    }

    const log = await client.query(
      `INSERT INTO stream_logs (user_id, track, artist, platform, created_at)
       VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
      [userId, track, artist || null, platform]
    );

    // Atomic in one statement: bump both stream counters, and credit
    // exactly 1 HP only on every 10th total lifetime stream (checked via
    // modulo on the NEW value, all inside the same UPDATE so there's no
    // window for a race condition between two near-simultaneous scrobbles
    // to both think they're "the 10th" and double-credit HP).
    const updated = await client.query(
      `UPDATE profiles SET
         daily_stream_count = daily_stream_count + 1,
         weekly_stream_count = weekly_stream_count + 1,
         total_lifetime_streams = total_lifetime_streams + 1,
         current_hp = current_hp + CASE WHEN (total_lifetime_streams + 1) % $1 = 0 THEN 1 ELSE 0 END,
         total_hp = total_hp + CASE WHEN (total_lifetime_streams + 1) % $1 = 0 THEN 1 ELSE 0 END
       WHERE id = $2
       RETURNING id, current_hp, total_hp, streak_count, daily_stream_count, weekly_stream_count, total_lifetime_streams`,
      [STREAMS_PER_HP, userId]
    );

    await client.query('COMMIT');
    return { log: log.rows[0], profile: updated.rows[0] };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

app.post('/api/scrobble', requireAuth, async (req, res) => {
  try {
    const result = await logStreamForUser(req.user.id, req.body);
    if (result.error) return res.status(400).json({ error: result.error });
    if (result.duplicate) return res.status(200).json({ success: true, duplicate: true });
    res.status(201).json({ success: true, log: result.log, profile: result.profile });
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

// Real count across ALL members in the last 24h — a genuine COUNT query,
// not the capped 30-row /recent list, so this stays accurate even once
// more than 30 streams happen in a day.
app.get('/api/streams/count-24h', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COUNT(*)::int AS count FROM stream_logs WHERE created_at > NOW() - INTERVAL '24 hours'`
    );
    res.json({ count: result.rows[0].count });
  } catch (err) {
    res.status(500).json({ error: 'Server error counting streams.' });
  }
});

// ==========================================
// REAL EXTERNAL SCROBBLER INTEGRATION
// Web Scrobbler's own webhook feature (v3.2.0+), and a ListenBrainz-API-
// compatible endpoint that both Web Scrobbler's alternate mode and Pano
// Scrobbler can point at (same pattern self-hosted scrobblers like Maloja
// use — verified against their real, published API docs before building
// this, not guessed).
//
// Neither of these use JWT auth — external tools can't send an
// Authorization: Bearer <jwt> header, so a long-lived per-user secret
// token stands in for it instead: in the URL path for Web Scrobbler's
// webhook, or a bare "Authorization: Token <token>" header for the
// ListenBrainz-compatible route (matching ListenBrainz's own real
// protocol).
// ==========================================

app.get('/api/me/scrobble-urls', requireAuth, async (req, res) => {
  try {
    let result = await pool.query('SELECT scrobble_token FROM profiles WHERE id = $1', [req.user.id]);
    let token = result.rows[0] && result.rows[0].scrobble_token;
    if (!token) {
      token = crypto.randomBytes(24).toString('hex');
      await pool.query('UPDATE profiles SET scrobble_token = $1 WHERE id = $2', [token, req.user.id]);
    }
    const base = `${req.protocol}://${req.get('host')}`;
    res.json({
      token,
      webScrobblerWebhookUrl: `${base}/webhook/web-scrobbler/${token}`,
      listenBrainzApiUrl: `${base}/webhook/listenbrainz`,
      listenBrainzToken: token,
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error generating scrobble URLs.' });
  }
});

async function findUserByScrobbleToken(token) {
  if (!token) return null;
  const result = await pool.query('SELECT id FROM profiles WHERE scrobble_token = $1', [token]);
  return result.rows.length > 0 ? result.rows[0].id : null;
}

// Web Scrobbler's real webhook payload shape (verified against their
// published wiki): { eventName, data: { song: { processed, parsed } } }.
// MUST always return 200, even when ignoring an event — Web Scrobbler
// treats any non-200 response as a scrobbling failure.
app.post('/webhook/web-scrobbler/:token', async (req, res) => {
  try {
    const userId = await findUserByScrobbleToken(req.params.token);
    if (!userId) return res.status(200).json({ ignored: true, reason: 'unknown token' });

    const { eventName, data } = req.body || {};
    if (eventName !== 'scrobble' || !data || !data.song) {
      return res.status(200).json({ ignored: true, reason: 'not a scrobble event' });
    }
    const song = data.song;
    // Same priority order Web Scrobbler's own code uses internally:
    // processed metadata (post-editing) wins over raw parsed metadata.
    const track = (song.processed && song.processed.track) || (song.parsed && song.parsed.track);
    const artist = (song.processed && song.processed.artist) || (song.parsed && song.parsed.artist);
    if (!track) return res.status(200).json({ ignored: true, reason: 'no track title' });

    await logStreamForUser(userId, { track, artist, platform: 'Web Scrobbler' });
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Web Scrobbler webhook error:', err);
    // Still 200 — an internal error on our side shouldn't make the
    // extension think ITS scrobble failed and retry indefinitely.
    res.status(200).json({ ignored: true, reason: 'server error' });
  }
});

// Real ListenBrainz-compatible submit-listens endpoint. Covers Web
// Scrobbler's "Custom ListenBrainz" mode AND Pano Scrobbler, since both
// speak the same real, documented ListenBrainz protocol.
app.post('/webhook/listenbrainz/1/submit-listens', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Token ') ? authHeader.slice(6) : null;
    const userId = await findUserByScrobbleToken(token);
    if (!userId) return res.status(401).json({ code: 401, error: 'Invalid or missing user token.' });

    const { listen_type, payload } = req.body || {};
    // "playing_now" is a preview ping, not a completed listen — only
    // "single" (and "import", batch submissions) actually count.
    if (listen_type !== 'single' && listen_type !== 'import') {
      return res.status(200).json({ status: 'ok' });
    }
    const listens = Array.isArray(payload) ? payload : [];
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    // Both real clients identify themselves in their User-Agent — detect
    // which one actually sent this rather than assuming, since this one
    // endpoint serves both Pano Scrobbler and Web Scrobbler's alternate mode.
    const platform = ua.includes('web-scrobbler') || ua.includes('webscrobbler') ? 'Web Scrobbler' : 'Pano Scrobbler';
    for (const listen of listens) {
      const meta = listen.track_metadata || {};
      if (!meta.track_name) continue;
      await logStreamForUser(userId, { track: meta.track_name, artist: meta.artist_name, platform });
    }
    res.status(200).json({ status: 'ok' });
  } catch (err) {
    console.error('ListenBrainz-compatible webhook error:', err);
    res.status(500).json({ code: 500, error: 'Server error.' });
  }
});

// Real ListenBrainz-compatible token validation. Pano Scrobbler (and Web
// Scrobbler's "Verify" button) call this before accepting your ListenBrainz
// instance settings — without it, Verify 404s even when the URL and token
// are both correct. Matches ListenBrainz's real, documented response shape
// exactly: { code, message, valid, user_name }. Accepts the token either
// via "Authorization: Token <token>" header (what real clients send) or a
// ?token= query param (ListenBrainz's own documented fallback).
app.get('/webhook/listenbrainz/1/validate-token', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const headerToken = authHeader.startsWith('Token ') ? authHeader.slice(6).trim() : null;
    const token = headerToken || (req.query.token ? String(req.query.token).trim() : null);

    // TEMP DEBUG — remove once Pano verifies successfully. Logs exactly
    // what arrived so a token mismatch can be seen in Render's Logs tab
    // instead of guessed at. Never logs the full token, only its length
    // and first/last few characters, so it's still safe to leave visible.
    console.log('[validate-token] authHeader present:', !!authHeader, '| query.token present:', !!req.query.token, '| resolved token length:', token ? token.length : 0, '| token preview:', token ? (token.slice(0, 6) + '...' + token.slice(-6)) : 'none');

    if (!token) {
      return res.status(200).json({ code: 200, message: 'No token provided.', valid: false });
    }

    const result = await pool.query('SELECT username FROM profiles WHERE scrobble_token = $1', [token]);
    console.log('[validate-token] matched a profile:', result.rows.length > 0);
    if (result.rows.length === 0) {
      return res.status(200).json({ code: 200, message: 'Token invalid.', valid: false });
    }

    res.status(200).json({
      code: 200,
      message: 'Token valid.',
      valid: true,
      user_name: result.rows[0].username,
    });
  } catch (err) {
    console.error('validate-token error:', err);
    res.status(500).json({ code: 500, error: 'Server error validating token.' });
  }
});

// ==========================================
// SELF-SERVICE STATS (a user updating their OWN hp/streak/streams)
// ==========================================

const STAT_COLUMNS = {
  currentHp: 'current_hp', totalHp: 'total_hp', streakCount: 'streak_count',
  dailyStreamCount: 'daily_stream_count', weeklyStreamCount: 'weekly_stream_count',
  totalLifetimeStreams: 'total_lifetime_streams',
};

app.post('/api/me/stats/increment', requireAuth, async (req, res) => {
  try {
    const sets = [];
    const values = [];
    let i = 1;
    for (const [key, column] of Object.entries(STAT_COLUMNS)) {
      if (typeof req.body[key] === 'number' && req.body[key] !== 0) {
        sets.push(`${column} = ${column} + $${i}`);
        values.push(req.body[key]);
        i++;
      }
    }
    if (sets.length === 0) return res.status(400).json({ error: 'No valid stat fields provided.' });
    values.push(req.user.id);
    const result = await pool.query(
      `UPDATE profiles SET ${sets.join(', ')} WHERE id = $${i} RETURNING id, current_hp, total_hp, streak_count, daily_stream_count, weekly_stream_count, total_lifetime_streams`,
      values
    );
    res.json({ success: true, profile: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error updating stats.' });
  }
});

app.post('/api/me/stats/reset', requireAuth, async (req, res) => {
  try {
    const { scope } = req.body; // 'daily' or 'weekly'
    let query;
    if (scope === 'weekly') {
      query = `UPDATE profiles SET current_hp = 0, weekly_stream_count = 0 WHERE id = $1 RETURNING id, current_hp, total_hp, streak_count, daily_stream_count, weekly_stream_count, total_lifetime_streams`;
    } else if (scope === 'daily') {
      query = `UPDATE profiles SET daily_stream_count = 0 WHERE id = $1 RETURNING id, current_hp, total_hp, streak_count, daily_stream_count, weekly_stream_count, total_lifetime_streams`;
    } else {
      return res.status(400).json({ error: 'scope must be "daily" or "weekly".' });
    }
    const result = await pool.query(query, [req.user.id]);
    res.json({ success: true, profile: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error resetting stats.' });
  }
});

// Combined marker-set + conditional-zero, used atomically by the reset
// engine so "record that daily/weekly reset X was applied" and "zero the
// relevant counters" happen in one query, not two separate round trips
// that could race against each other.
app.post('/api/me/reset-engine', requireAuth, async (req, res) => {
  try {
    const { markers, zeroDaily, zeroWeekly } = req.body || {};
    const sets = [];
    const values = [];
    let i = 1;
    if (markers && typeof markers.lastDailyResetApplied === 'number') {
      sets.push(`last_daily_reset_applied = $${i}`); values.push(markers.lastDailyResetApplied); i++;
    }
    if (markers && typeof markers.lastWeeklyResetApplied === 'number') {
      sets.push(`last_weekly_reset_applied = $${i}`); values.push(markers.lastWeeklyResetApplied); i++;
    }
    if (zeroDaily) sets.push(`daily_stream_count = 0`);
    if (zeroWeekly) sets.push(`current_hp = 0, weekly_stream_count = 0`);
    if (sets.length === 0) return res.status(400).json({ error: 'Nothing to update.' });
    values.push(req.user.id);
    const result = await pool.query(
      `UPDATE profiles SET ${sets.join(', ')} WHERE id = $${i} RETURNING id, current_hp, total_hp, streak_count, daily_stream_count, weekly_stream_count, total_lifetime_streams, last_daily_reset_applied, last_weekly_reset_applied`,
      values
    );
    res.json({ success: true, profile: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error updating reset engine state.' });
  }
});

// ==========================================
// SHARED CONFIG (admin-managed: community channels, playlists, voting reward)
// ==========================================

app.get('/api/config/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT data FROM shared_config WHERE id = $1', [req.params.id]);
    res.json(result.rows.length > 0 ? result.rows[0].data : null);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching config.' });
  }
});

app.put('/api/config/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO shared_config (id, data, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (id) DO UPDATE SET data = $2, updated_at = NOW()`,
      [req.params.id, req.body]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error saving config.' });
  }
});

// ==========================================
// NOTIFICATIONS
// ==========================================

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 30');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching notifications.' });
  }
});

app.post('/api/notifications', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { text, severity } = req.body;
    if (!text) return res.status(400).json({ error: 'text is required.' });
    const result = await pool.query(
      `INSERT INTO notifications (text, severity, created_at) VALUES ($1, $2, NOW()) RETURNING *`,
      [text, severity || 'standard']
    );
    res.status(201).json({ success: true, notification: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error publishing notification.' });
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

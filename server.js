const express = require('express');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(express.static(path.join(__dirname, 'public')));

// ---- Postgres pool (Heroku friendly SSL) ----
const isProd = process.env.NODE_ENV === 'production';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false,
});

// ---- Simple helpers ----
const LLAVE_RE = /^[A-Z0-9]{6}$/; // 6 chars, caps+digits
function normLlave(s) { return String(s || '').trim().toUpperCase(); }
function assert(cond, msg, code = 400) { if (!cond) { const e = new Error(msg); e.status = code; throw e; } }

// ---- DB migrate (idempotent) ----
async function migrate() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    full_name TEXT NOT NULL,
    llave CHAR(6) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`);

  await pool.query(`CREATE TABLE IF NOT EXISTS debts (
    id UUID PRIMARY KEY,
    sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,   -- owes
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- is owed
    qty INTEGER NOT NULL DEFAULT 1 CHECK (qty > 0),
    message TEXT,
    origin TEXT NOT NULL DEFAULT 'sent' CHECK (origin IN ('sent','requested')),
    sender_marked_paid BOOLEAN NOT NULL DEFAULT FALSE,
    recipient_marked_paid BOOLEAN NOT NULL DEFAULT FALSE,
    settled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`);

  // small index helpers
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_debts_participants ON debts (sender_id, recipient_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_llave ON users (llave);`);
}

// ---- Auth via X-LLAVE header or body.llave (toy) ----
async function auth(req, res, next) {
  try {
    const fromHeader = req.header('x-llave');
    const fromBody = req.body && req.body.llave;
    const llave = normLlave(fromHeader || fromBody);
    assert(LLAVE_RE.test(llave), 'Provide your 6-char llave in X-LLAVE header.');
    const { rows } = await pool.query('SELECT * FROM users WHERE llave = $1', [llave]);
    assert(rows[0], 'Unknown llave. Register first.', 401);
    req.user = rows[0];
    next();
  } catch (e) {
    next(e);
  }
}

// ---- Routes: health ----
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---- Routes: users ----
app.post('/api/users/register', async (req, res, next) => {
  try {
    let { full_name, llave } = req.body;
    assert(full_name && String(full_name).trim().length >= 2, 'Full name required.');
    llave = normLlave(llave);
    assert(LLAVE_RE.test(llave), 'Llave must be 6 chars [A-Z0-9].');

    const { rows: existing } = await pool.query('SELECT 1 FROM users WHERE llave=$1', [llave]);
    assert(existing.length === 0, 'Llave already taken.');

    const id = uuidv4();
    const { rows } = await pool.query(
      'INSERT INTO users (id, full_name, llave) VALUES ($1,$2,$3) RETURNING id, full_name, llave, created_at',
      [id, full_name.trim(), llave]
    );
    res.status(201).json(rows[0]);
  } catch (e) { next(e); }
});

app.post('/api/users/login', async (req, res, next) => {
  try {
    const llave = normLlave(req.body.llave);
    assert(LLAVE_RE.test(llave), 'Llave must be 6 chars [A-Z0-9].');
    const { rows } = await pool.query('SELECT id, full_name, llave, created_at FROM users WHERE llave=$1', [llave]);
    assert(rows[0], 'Unknown llave.');
    res.json(rows[0]);
  } catch (e) { next(e); }
});

app.get('/api/users/lookup/:llave', auth, async (req, res, next) => {
  try {
    const target = normLlave(req.params.llave);
    const { rows } = await pool.query('SELECT id, full_name, llave FROM users WHERE llave=$1', [target]);
    assert(rows[0], 'User not found');
    res.json(rows[0]);
  } catch (e) { next(e); }
});

// ---- Routes: debts ----
function shapeDebt(r) {
  const status = r.settled_at ? 'settled' : (r.sender_marked_paid || r.recipient_marked_paid) ? 'half-marked' : 'pending';
  return {
    id: r.id,
    qty: r.qty,
    message: r.message,
    origin: r.origin, // 'sent' | 'requested'
    sender_marked_paid: r.sender_marked_paid,
    recipient_marked_paid: r.recipient_marked_paid,
    settled_at: r.settled_at,
    created_at: r.created_at,
    status,
    sender: { id: r.sender_id, full_name: r.sender_name, llave: r.sender_llave },
    recipient: { id: r.recipient_id, full_name: r.recipient_name, llave: r.recipient_llave },
  };
}

app.get('/api/debts', auth, async (req, res, next) => {
  try {
    const me = req.user.id;
    const { rows } = await pool.query(
      `SELECT d.*,
              su.full_name AS sender_name, su.llave AS sender_llave,
              ru.full_name AS recipient_name, ru.llave AS recipient_llave
       FROM debts d
       JOIN users su ON su.id = d.sender_id
       JOIN users ru ON ru.id = d.recipient_id
       WHERE d.sender_id=$1 OR d.recipient_id=$1
       ORDER BY d.created_at DESC`, [me]);
    res.json(rows.map(shapeDebt));
  } catch (e) { next(e); }
});

// send: I (sender) owe recipient 1..n empanadas
app.post('/api/debts/send', auth, async (req, res, next) => {
  try {
    const me = req.user;
    const toLlave = normLlave(req.body.to_llave);
    const qty = Math.max(1, parseInt(req.body.qty || '1', 10));
    const message = (req.body.message || '').slice(0, 240);

    assert(LLAVE_RE.test(toLlave), 'to_llave must be 6 chars');
    const { rows: u } = await pool.query('SELECT id FROM users WHERE llave=$1', [toLlave]);
    assert(u[0], 'Recipient not found');
    assert(u[0].id !== me.id, 'Cannot send to yourself');

    const id = uuidv4();
    const { rows } = await pool.query(
      `INSERT INTO debts (id, sender_id, recipient_id, qty, message, origin)
       VALUES ($1,$2,$3,$4,$5,'sent')
       RETURNING *`,
      [id, me.id, u[0].id, qty, message]
    );
    const shaped = shapeDebt({ ...rows[0], sender_name: req.user.full_name, sender_llave: req.user.llave, recipient_name: '', recipient_llave: toLlave });
    res.status(201).json(shaped);
  } catch (e) { next(e); }
});

// request: I ask target to owe me (i.e., flips roles)
app.post('/api/debts/request', auth, async (req, res, next) => {
  try {
    const me = req.user; // requester becomes recipient in debt
    const fromLlave = normLlave(req.body.from_llave);
    const qty = Math.max(1, parseInt(req.body.qty || '1', 10));
    const message = (req.body.message || '').slice(0, 240);

    assert(LLAVE_RE.test(fromLlave), 'from_llave must be 6 chars');
    const { rows: u } = await pool.query('SELECT id FROM users WHERE llave=$1', [fromLlave]);
    assert(u[0], 'Target not found');
    assert(u[0].id !== me.id, 'Cannot request from yourself');

    const id = uuidv4();
    const { rows } = await pool.query(
      `INSERT INTO debts (id, sender_id, recipient_id, qty, message, origin)
       VALUES ($1,$2,$3,$4,$5,'requested')
       RETURNING *`,
      [id, u[0].id, me.id, qty, message]
    );
    const shaped = shapeDebt({ ...rows[0], sender_name: '', sender_llave: fromLlave, recipient_name: req.user.full_name, recipient_llave: req.user.llave });
    res.status(201).json(shaped);
  } catch (e) { next(e); }
});

// mark as paid (each party marks once). When both true -> settled_at set.
app.post('/api/debts/:id/mark', auth, async (req, res, next) => {
  try {
    const me = req.user;
    const { id } = req.params;
    const { rows } = await pool.query('SELECT * FROM debts WHERE id=$1', [id]);
    assert(rows[0], 'Debt not found', 404);
    const d = rows[0];

    assert([d.sender_id, d.recipient_id].includes(me.id), 'Not your debt', 403);

    let setSender = d.sender_marked_paid;
    let setRecipient = d.recipient_marked_paid;

    if (me.id === d.sender_id) setSender = true;
    if (me.id === d.recipient_id) setRecipient = true;

    const settled = setSender && setRecipient ? new Date() : null;

    const upd = await pool.query(
      `UPDATE debts SET sender_marked_paid=$1, recipient_marked_paid=$2, settled_at=$3
       WHERE id=$4 RETURNING *`,
      [setSender, setRecipient, settled, id]
    );

    res.json(upd.rows[0]);
  } catch (e) { next(e); }
});

// undo my mark (in case of mistake)
app.post('/api/debts/:id/unmark', auth, async (req, res, next) => {
  try {
    const me = req.user;
    const { id } = req.params;
    const { rows } = await pool.query('SELECT * FROM debts WHERE id=$1', [id]);
    assert(rows[0], 'Debt not found', 404);
    const d = rows[0];
    assert(!d.settled_at, 'Already settled');

    let setSender = d.sender_marked_paid;
    let setRecipient = d.recipient_marked_paid;

    if (me.id === d.sender_id) setSender = false;
    if (me.id === d.recipient_id) setRecipient = false;

    const upd = await pool.query(
      `UPDATE debts SET sender_marked_paid=$1, recipient_marked_paid=$2, settled_at=NULL
       WHERE id=$3 RETURNING *`,
      [setSender, setRecipient, id]
    );
    res.json(upd.rows[0]);
  } catch (e) { next(e); }
});

// stats for me
app.get('/api/stats/me', auth, async (req, res, next) => {
  try {
    const me = req.user.id;
    const pending = await pool.query(
      `SELECT sender_id, recipient_id, qty,
              sender_marked_paid, recipient_marked_paid
         FROM debts
        WHERE settled_at IS NULL AND (sender_id=$1 OR recipient_id=$1)`,[me]
    );

    let iOwe = 0, oweMe = 0;
    const perFriend = {}; // llave -> { name, iOwe, oweMe }

    for (const r of pending.rows) {
      const isSender = r.sender_id === me;
      if (isSender) iOwe += r.qty; else oweMe += r.qty;
    }

    const friendRows = await pool.query(
      `SELECT d.*, su.full_name sname, su.llave sllave, ru.full_name rname, ru.llave rllave
         FROM debts d
         JOIN users su ON su.id=d.sender_id
         JOIN users ru ON ru.id=d.recipient_id
        WHERE d.settled_at IS NULL AND (d.sender_id=$1 OR d.recipient_id=$1)`,[me]
    );

    for (const r of friendRows.rows) {
      const other = r.sender_id === me ? { id: r.recipient_id, name: r.rname, llave: r.rllave } : { id: r.sender_id, name: r.sname, llave: r.sllave };
      if (!perFriend[other.llave]) perFriend[other.llave] = { name: other.name, iOwe: 0, oweMe: 0 };
      if (r.sender_id === me) perFriend[other.llave].iOwe += r.qty; else perFriend[other.llave].oweMe += r.qty;
    }

    res.json({ iOwe, oweMe, net: oweMe - iOwe, perFriend });
  } catch (e) { next(e); }
});

// ---- Error handler ----
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

// ---- Boot ----
(async () => {
  await migrate();
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Empanada server on :${port}`));
})();

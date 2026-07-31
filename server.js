const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const dbPath = path.join(__dirname, 'app.db');
const db = new sqlite3.Database(dbPath);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: 'growtech-tray-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 },
  })
);

app.use(express.static(__dirname));

function authRequired(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Please log in to use the tray tracking system.' });
  }
  next();
}

function initDatabase() {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'staff'
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        variety TEXT NOT NULL,
        location TEXT NOT NULL,
        dateTaken TEXT NOT NULL,
        traysTaken INTEGER NOT NULL,
        dateReturned TEXT,
        traysDamaged INTEGER NOT NULL DEFAULT 0,
        createdBy TEXT NOT NULL,
        updatedAt TEXT NOT NULL
      )
    `);

    db.get('SELECT COUNT(*) AS count FROM users', (err, row) => {
      if (err) {
        console.error('Error checking users:', err.message);
        return;
      }

      if (row.count === 0) {
        db.run(
          'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
          ['admin', 'admin123', 'admin']
        );
        db.run(
          'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
          ['staff', 'staff123', 'staff']
        );
      }
    });
  });
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', users: 'ready' });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get(
    'SELECT id, username, role FROM users WHERE username = ? AND password = ?',
    [username, password],
    (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Login failed.' });
      }

      if (!user) {
        return res.status(401).json({ message: 'Invalid username or password.' });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
      };

      return res.json({
        message: 'Login successful',
        user: req.session.user,
      });
    }
  );
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Not logged in' });
  }

  return res.json({ user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out successfully' });
  });
});

app.get('/api/records', authRequired, (req, res) => {
  db.all(
    'SELECT * FROM records ORDER BY updatedAt DESC',
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: 'Unable to load records.' });
      }

      return res.json(rows);
    }
  );
});

app.post('/api/records', authRequired, (req, res) => {
  const {
    id,
    name,
    phone,
    variety,
    location,
    dateTaken,
    traysTaken,
    dateReturned,
    traysDamaged,
  } = req.body;

  const timestamp = new Date().toISOString();
  const safeTraysTaken = Number(traysTaken) || 0;
  const safeDamaged = Number(traysDamaged) || 0;

  if (!name || !phone || !variety || !location || !dateTaken) {
    return res.status(400).json({ message: 'Please complete all required fields.' });
  }

  if (id) {
    db.run(
      `UPDATE records
       SET name = ?, phone = ?, variety = ?, location = ?, dateTaken = ?, traysTaken = ?, dateReturned = ?, traysDamaged = ?, updatedAt = ?
       WHERE id = ?`,
      [name, phone, variety, location, dateTaken, safeTraysTaken, dateReturned || null, safeDamaged, timestamp, id],
      function (err) {
        if (err) {
          return res.status(500).json({ message: 'Unable to update record.' });
        }

        return res.json({ message: 'Record updated successfully', id });
      }
    );
  } else {
    db.run(
      `INSERT INTO records (name, phone, variety, location, dateTaken, traysTaken, dateReturned, traysDamaged, createdBy, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, phone, variety, location, dateTaken, safeTraysTaken, dateReturned || null, safeDamaged, req.session.user.username, timestamp],
      function (err) {
        if (err) {
          return res.status(500).json({ message: 'Unable to save record.' });
        }

        return res.json({ message: 'Record saved successfully', id: this.lastID });
      }
    );
  }
});

app.delete('/api/records/:id', authRequired, (req, res) => {
  const { id } = req.params;

  db.run('DELETE FROM records WHERE id = ?', [id], function (err) {
    if (err) {
      return res.status(500).json({ message: 'Unable to delete record.' });
    }

    return res.json({ message: 'Record deleted successfully' });
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'form.html'));
});

initDatabase();

app.listen(PORT, () => {
  console.log(`Growtech tray tracking app is running on http://localhost:${PORT}`);
  console.log('Demo login accounts: admin/admin123 and staff/staff123');
});

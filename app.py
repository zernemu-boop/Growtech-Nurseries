from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request, session, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'growtech-tray-secret'
DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect_db()
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff'
        )
        '''
    )
    conn.execute(
        '''
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
        '''
    )

    user_count = conn.execute('SELECT COUNT(*) AS count FROM users').fetchone()['count']
    if user_count == 0:
        conn.executemany(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [
                ('admin', generate_password_hash('admin123'), 'admin'),
                ('staff', generate_password_hash('staff123'), 'staff'),
            ],
        )
    else:
        legacy_users = conn.execute('SELECT id, username, password FROM users').fetchall()
        for user in legacy_users:
            stored_password = user['password']
            if not stored_password.startswith('scrypt:') and not stored_password.startswith('pbkdf2:'):
                conn.execute(
                    'UPDATE users SET password = ? WHERE id = ?',
                    (generate_password_hash(stored_password), user['id']),
                )

    conn.commit()
    conn.close()


@app.before_request
def _ensure_db() -> None:
    init_db()


@app.get('/api/health')
def health() -> Any:
    return jsonify({'status': 'ok'})


@app.post('/api/login')
def login() -> Any:
    payload = request.get_json(silent=True) or {}
    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''

    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    conn = connect_db()
    user = conn.execute(
        'SELECT id, username, role, password FROM users WHERE username = ?',
        (username,),
    ).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid username or password.'}), 401

    session['user'] = {
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
    }
    return jsonify({'message': 'Login successful', 'user': session['user']})


@app.get('/api/me')
def current_user() -> Any:
    if 'user' not in session:
        return jsonify({'message': 'Not logged in'}), 401
    return jsonify({'user': session['user']})


@app.post('/api/logout')
def logout() -> Any:
    session.clear()
    return jsonify({'message': 'Logged out successfully'})


def require_login() -> Any | None:
    if 'user' not in session:
        return jsonify({'message': 'Please log in to use the tray tracking system.'}), 401
    return None


def require_admin() -> Any | None:
    auth_error = require_login()
    if auth_error:
        return auth_error
    if session['user']['role'] != 'admin':
        return jsonify({'message': 'Only admins can manage users.'}), 403
    return None


@app.get('/api/users')
def get_users() -> Any:
    auth_error = require_admin()
    if auth_error:
        return auth_error

    conn = connect_db()
    rows = conn.execute('SELECT id, username, role FROM users ORDER BY id ASC').fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.get('/api/admin/summary')
def get_admin_summary() -> Any:
    auth_error = require_admin()
    if auth_error:
        return auth_error

    conn = connect_db()
    user_count = conn.execute('SELECT COUNT(*) AS count FROM users').fetchone()['count']
    admin_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").fetchone()['count']
    staff_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'staff'").fetchone()['count']
    record_count = conn.execute('SELECT COUNT(*) AS count FROM records').fetchone()['count']
    pending_records = conn.execute("SELECT COUNT(*) AS count FROM records WHERE dateReturned IS NULL OR dateReturned = ''").fetchone()['count']
    damaged_trays = conn.execute('SELECT COALESCE(SUM(traysDamaged), 0) AS total FROM records').fetchone()['total']
    conn.close()

    return jsonify({
        'total_users': user_count,
        'admin_count': admin_count,
        'staff_count': staff_count,
        'total_records': record_count,
        'pending_records': pending_records,
        'damaged_trays': damaged_trays,
    })


@app.get('/api/audit')
def get_audit() -> Any:
    auth_error = require_admin()
    if auth_error:
        return auth_error

    conn = connect_db()
    rows = conn.execute(
        'SELECT id, name, phone, variety, location, dateTaken, traysTaken, dateReturned, traysDamaged, createdBy, updatedAt FROM records ORDER BY updatedAt DESC'
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.post('/api/users')
def create_user() -> Any:
    auth_error = require_admin()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    role = (payload.get('role') or 'staff').strip().lower()

    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    if role not in {'admin', 'staff'}:
        return jsonify({'message': 'Role must be admin or staff.'}), 400

    conn = connect_db()
    try:
        conn.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (username, generate_password_hash(password), role),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'message': 'That username already exists.'}), 409
    finally:
        conn.close()

    return jsonify({'message': 'User created successfully'})


@app.patch('/api/users/<int:user_id>')
def update_user(user_id: int) -> Any:
    auth_error = require_admin()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    role = (payload.get('role') or '').strip().lower()

    if role not in {'admin', 'staff'}:
        return jsonify({'message': 'Role must be admin or staff.'}), 400

    if user_id == session['user']['id'] and role != 'admin':
        return jsonify({'message': 'You cannot demote your own admin account.'}), 403

    conn = connect_db()
    conn.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User role updated successfully'})


@app.delete('/api/users/<int:user_id>')
def delete_user(user_id: int) -> Any:
    auth_error = require_admin()
    if auth_error:
        return auth_error

    if user_id == session['user']['id']:
        return jsonify({'message': 'You cannot delete your own account.'}), 403

    conn = connect_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User deleted successfully'})


@app.get('/api/records')
def get_records() -> Any:
    auth_error = require_login()
    if auth_error:
        return auth_error

    conn = connect_db()
    rows = conn.execute('SELECT * FROM records ORDER BY updatedAt DESC').fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.post('/api/records')
def save_record() -> Any:
    auth_error = require_login()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    record_id = payload.get('id')
    name = (payload.get('name') or '').strip()
    phone = (payload.get('phone') or '').strip()
    variety = (payload.get('variety') or '').strip()
    location = (payload.get('location') or '').strip()
    date_taken = payload.get('dateTaken') or ''
    trays_taken = int(payload.get('traysTaken') or 0)
    date_returned = payload.get('dateReturned') or None
    trays_damaged = int(payload.get('traysDamaged') or 0)
    timestamp = datetime.now(timezone.utc).isoformat()

    if not all([name, phone, variety, location, date_taken]):
        return jsonify({'message': 'Please complete all required fields.'}), 400

    conn = connect_db()
    if record_id:
        conn.execute(
            '''
            UPDATE records
            SET name = ?, phone = ?, variety = ?, location = ?, dateTaken = ?, traysTaken = ?, dateReturned = ?, traysDamaged = ?, updatedAt = ?
            WHERE id = ?
            ''',
            (name, phone, variety, location, date_taken, trays_taken, date_returned, trays_damaged, timestamp, record_id),
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Record updated successfully', 'id': record_id})

    cursor = conn.execute(
        '''
        INSERT INTO records (name, phone, variety, location, dateTaken, traysTaken, dateReturned, traysDamaged, createdBy, updatedAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (name, phone, variety, location, date_taken, trays_taken, date_returned, trays_damaged, session['user']['username'], timestamp),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return jsonify({'message': 'Record saved successfully', 'id': new_id})


@app.delete('/api/records/<int:record_id>')
def delete_record(record_id: int) -> Any:
    auth_error = require_login()
    if auth_error:
        return auth_error

    if session['user']['role'] != 'admin':
        return jsonify({'message': 'Only admins can delete records.'}), 403

    conn = connect_db()
    conn.execute('DELETE FROM records WHERE id = ?', (record_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Record deleted successfully'})


@app.route('/')
def index() -> Any:
    return send_from_directory(os.path.dirname(__file__), 'form.html')


@app.route('/admin.html')
def admin_page() -> Any:
    return send_from_directory(os.path.dirname(__file__), 'admin.html')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

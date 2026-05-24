# database.py
# Updated: added session_log table for developer-level activity tracking.

import sqlite3
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from compliance_mapper import CONTROLS_DB

DB_FILE = "grc.db"


def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS controls (
            control_id       TEXT PRIMARY KEY,
            nist_function    TEXT,
            nist_description TEXT,
            iso_27001        TEXT,
            iso_description  TEXT,
            soc2_tsc         TEXT,
            soc2_description TEXT,
            pci_dss          TEXT,
            pci_description  TEXT,
            ndpa             TEXT,
            ndpa_description TEXT,
            gdpr             TEXT,
            gdpr_description TEXT,
            status           TEXT DEFAULT 'Not Assessed'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'viewer',
            is_active     INTEGER DEFAULT 0,
            created_at    TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            control_id TEXT,
            old_status TEXT,
            new_status TEXT,
            changed_by TEXT,
            changed_at TEXT
        )
    """)

    # Session log: developer-level activity tracking
    # Tracks every login, logout, page visit, export, and failed login
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS session_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            action     TEXT,
            detail     TEXT,
            ip_address TEXT,
            timestamp  TEXT
        )
    """)

    # Populate controls if empty
    cursor.execute("SELECT COUNT(*) FROM controls")
    if cursor.fetchone()[0] == 0:
        print("Initialising database with controls...")
        for control_id, details in CONTROLS_DB.items():
            cursor.execute("""
                INSERT INTO controls (
                    control_id, nist_function, nist_description,
                    iso_27001, iso_description,
                    soc2_tsc, soc2_description,
                    pci_dss, pci_description,
                    ndpa, ndpa_description,
                    gdpr, gdpr_description,
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                control_id,
                details["nist_function"],
                details["nist_description"],
                ", ".join(details["iso_27001"]),
                details["iso_description"],
                ", ".join(details["soc2_tsc"]),
                details["soc2_description"],
                ", ".join(details["pci_dss"]),
                details["pci_description"],
                ", ".join(details["ndpa"]),
                details["ndpa_description"],
                ", ".join(details.get("gdpr", ["N/A"])),
                details.get("gdpr_description", "Not directly applicable"),
                details["status"]
            ))
        print(f"Loaded {len(CONTROLS_DB)} controls.")

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        print("Creating default admin user...")
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "admin",
            generate_password_hash("admin123"),
            "admin",
            1,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        print("Default admin created. Username: admin / Password: admin123")

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# CONTROL FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_all_controls():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM controls ORDER BY nist_function, control_id")
    rows = cursor.fetchall()
    conn.close()
    return rows


def update_status(control_id, new_status, changed_by):
    valid_statuses = ["Compliant", "Partial", "Non-Compliant", "Not Assessed"]
    if new_status not in valid_statuses:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM controls WHERE control_id = ?", (control_id,))
    row = cursor.fetchone()
    old_status = row["status"] if row else "Unknown"
    cursor.execute("UPDATE controls SET status = ? WHERE control_id = ?", (new_status, control_id))
    cursor.execute("""
        INSERT INTO audit_log (control_id, old_status, new_status, changed_by, changed_at)
        VALUES (?, ?, ?, ?, ?)
    """, (control_id, old_status, new_status, changed_by,
          datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return True


def get_summary():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status, COUNT(*) as count FROM controls GROUP BY status")
    rows = cursor.fetchall()
    conn.close()
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}
    for row in rows:
        summary[row["status"]] = row["count"]
    return summary


def get_audit_log():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log ORDER BY changed_at DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# SESSION LOG FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def log_activity(username, action, detail, ip_address):
    """
    Write an activity record to the session log.
    Called from every route in app.py.

    username   = who did it (or 'anonymous' for failed logins)
    action     = what happened (LOGIN, LOGOUT, PAGE_VIEW, EXPORT, STATUS_UPDATE, etc.)
    detail     = extra context (which page, which export format, which control)
    ip_address = the user's IP address from the request
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO session_log (username, action, detail, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        action,
        detail,
        ip_address,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def get_session_log(limit=100):
    """Fetch the most recent session log entries, newest first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM session_log
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_session_stats():
    """
    Return summary statistics for the developer log dashboard.
    Total logins, unique users, failed logins, exports.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Total successful logins
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'LOGIN'")
    total_logins = cursor.fetchone()[0]

    # Unique users who have logged in
    cursor.execute("SELECT COUNT(DISTINCT username) FROM session_log WHERE action = 'LOGIN'")
    unique_users = cursor.fetchone()[0]

    # Failed login attempts
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'LOGIN_FAILED'")
    failed_logins = cursor.fetchone()[0]

    # Total exports
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'EXPORT'")
    total_exports = cursor.fetchone()[0]

    # Total status updates
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'STATUS_UPDATE'")
    total_updates = cursor.fetchone()[0]

    # Most active user
    cursor.execute("""
        SELECT username, COUNT(*) as count
        FROM session_log
        WHERE action = 'LOGIN'
        GROUP BY username
        ORDER BY count DESC
        LIMIT 1
    """)
    row = cursor.fetchone()
    most_active = row["username"] if row else "N/A"

    conn.close()
    return {
        "total_logins":   total_logins,
        "unique_users":   unique_users,
        "failed_logins":  failed_logins,
        "total_exports":  total_exports,
        "total_updates":  total_updates,
        "most_active":    most_active,
    }


# ─────────────────────────────────────────────────────────────────────────────
# USER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    return users


def verify_password(username, password):
    user = get_user_by_username(username)
    if not user:
        return None, "invalid"
    if not check_password_hash(user["password_hash"], password):
        return None, "invalid"
    if not user["is_active"]:
        return None, "inactive"
    return user, "ok"


def register_user(username, password):
    if get_user_by_username(username):
        return False, "Username already exists."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            generate_password_hash(password),
            "viewer",
            0,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        return True, "ok"
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def create_user_by_admin(username, password, role):
    if get_user_by_username(username):
        return False, "Username already exists."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            generate_password_hash(password),
            role,
            1,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        return True, "ok"
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def activate_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def deactivate_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def update_user_role(user_id, new_role):
    if new_role not in ["admin", "viewer"]:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return True


def change_password(user_id, current_password, new_password):
    user = get_user_by_id(user_id)
    if not user:
        return False, "User not found."
    if not check_password_hash(user["password_hash"], current_password):
        return False, "Current password is incorrect."
    if len(new_password) < 8:
        return False, "New password must be at least 8 characters."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()
    return True, "Password updated successfully."


def admin_reset_password(user_id, new_password):
    if len(new_password) < 8:
        return False, "Password must be at least 8 characters."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()
    return True, "Password reset successfully."


def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

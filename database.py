# database.py
# Updated: added assets and vulnerabilities tables for vulnerability tracker.

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

    # Assets table: tracks organizational assets that vulnerabilities are logged against
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            category      TEXT NOT NULL,
            description   TEXT,
            owner         TEXT,
            created_at    TEXT
        )
    """)

    # Vulnerabilities table: CVEs logged against assets with risk ratings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id        INTEGER NOT NULL,
            cve_id          TEXT,
            cvss_score      REAL,
            risk_rating     TEXT,
            description     TEXT,
            affected_system TEXT,
            status          TEXT DEFAULT 'Open',
            identified_date TEXT,
            resolved_date   TEXT,
            assigned_to     TEXT,
            created_at      TEXT,
            FOREIGN KEY (asset_id) REFERENCES assets (id)
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
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO session_log (username, action, detail, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username, action, detail, ip_address,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def get_session_log(limit=1000):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM session_log ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_session_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'LOGIN'")
    total_logins = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT username) FROM session_log WHERE action = 'LOGIN'")
    unique_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'LOGIN_FAILED'")
    failed_logins = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'EXPORT'")
    total_exports = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM session_log WHERE action = 'STATUS_UPDATE'")
    total_updates = cursor.fetchone()[0]
    cursor.execute("""
        SELECT username, COUNT(*) as count FROM session_log
        WHERE action = 'LOGIN' GROUP BY username ORDER BY count DESC LIMIT 1
    """)
    row = cursor.fetchone()
    most_active = row["username"] if row else "N/A"
    conn.close()
    return {
        "total_logins": total_logins, "unique_users": unique_users,
        "failed_logins": failed_logins, "total_exports": total_exports,
        "total_updates": total_updates, "most_active": most_active,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ASSET FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_all_assets():
    """Fetch all assets, ordered by most recently created."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_asset_by_id(asset_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def create_asset(name, category, description, owner):
    """Add a new asset. Returns the new asset's ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO assets (name, category, description, owner, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        name, category, description, owner,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def delete_asset(asset_id):
    """Delete an asset and all its associated vulnerabilities."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities WHERE asset_id = ?", (asset_id,))
    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def calculate_risk_rating(cvss_score):
    """
    Convert a CVSS score (0.0 - 10.0) into a risk rating category.
    Standard CVSS v3.1 severity ranges.
    """
    if cvss_score is None:
        return "Unrated"
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score > 0:
        return "Low"
    else:
        return "Unrated"


def get_all_vulnerabilities():
    """
    Fetch all vulnerabilities joined with their asset details.
    Ordered by CVSS score descending so highest risk shows first.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            vulnerabilities.*,
            assets.name AS asset_name,
            assets.category AS asset_category
        FROM vulnerabilities
        JOIN assets ON vulnerabilities.asset_id = assets.id
        ORDER BY vulnerabilities.cvss_score DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_vulnerability_by_id(vuln_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT vulnerabilities.*, assets.name AS asset_name, assets.category AS asset_category
        FROM vulnerabilities
        JOIN assets ON vulnerabilities.asset_id = assets.id
        WHERE vulnerabilities.id = ?
    """, (vuln_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def create_vulnerability(asset_id, cve_id, cvss_score, description, affected_system,
                          identified_date, assigned_to):
    """Add a new vulnerability. Risk rating is auto-calculated from CVSS score."""
    risk_rating = calculate_risk_rating(cvss_score)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vulnerabilities (
            asset_id, cve_id, cvss_score, risk_rating, description,
            affected_system, status, identified_date, resolved_date,
            assigned_to, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        asset_id, cve_id, cvss_score, risk_rating, description,
        affected_system, "Open", identified_date, None,
        assigned_to, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def update_vulnerability_status(vuln_id, new_status):
    """
    Update a vulnerability's remediation status.
    If marked Resolved, automatically sets resolved_date to today.
    """
    valid_statuses = ["Open", "In Progress", "Resolved", "Accepted Risk"]
    if new_status not in valid_statuses:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    if new_status == "Resolved":
        cursor.execute("""
            UPDATE vulnerabilities SET status = ?, resolved_date = ? WHERE id = ?
        """, (new_status, datetime.date.today().strftime("%Y-%m-%d"), vuln_id))
    else:
        cursor.execute("UPDATE vulnerabilities SET status = ? WHERE id = ?", (new_status, vuln_id))
    conn.commit()
    conn.close()
    return True


def delete_vulnerability(vuln_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()


def get_vulnerability_summary():
    """Count vulnerabilities by risk rating for the summary cards."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT risk_rating, COUNT(*) as count FROM vulnerabilities GROUP BY risk_rating")
    rows = cursor.fetchall()
    conn.close()
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unrated": 0}
    for row in rows:
        summary[row["risk_rating"]] = row["count"]
    return summary


def get_vulnerability_status_summary():
    """Count vulnerabilities by remediation status."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status, COUNT(*) as count FROM vulnerabilities GROUP BY status")
    rows = cursor.fetchall()
    conn.close()
    summary = {"Open": 0, "In Progress": 0, "Resolved": 0, "Accepted Risk": 0}
    for row in rows:
        summary[row["status"]] = row["count"]
    return summary


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
            username, generate_password_hash(password), "viewer", 0,
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
            username, generate_password_hash(password), role, 1,
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

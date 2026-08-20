# database.py
# Updated: added risks table for the Risk Scoring Engine (likelihood x impact matrix).

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
            email         TEXT,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'viewer',
            is_active     INTEGER DEFAULT 0,
            created_at    TEXT
        )
    """)

    # Migration: add email column if the table already existed without it
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = [row["name"] for row in cursor.fetchall()]
    if "email" not in existing_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")

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

    # Risks table: the Enterprise Risk Register.
    # source_type tells us where the risk came from: 'Control', 'Vulnerability', or 'Manual'
    # source_ref stores the control_id or vulnerability id it was generated from (NULL for manual)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS risks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            title           TEXT NOT NULL,
            description     TEXT,
            source_type     TEXT DEFAULT 'Manual',
            source_ref      TEXT,
            likelihood      INTEGER NOT NULL,
            impact          INTEGER NOT NULL,
            risk_score      INTEGER,
            risk_rating     TEXT,
            status          TEXT DEFAULT 'Open',
            owner           TEXT,
            identified_date TEXT,
            reviewed_date   TEXT,
            created_at      TEXT
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
        import os
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "admin",
            admin_email,
            generate_password_hash("admin123"),
            "admin",
            1,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        print(f"Default admin created. Username: admin / Password: admin123 / Email: {admin_email}")

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


def get_control_by_id(control_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM controls WHERE control_id = ?", (control_id,))
    row = cursor.fetchone()
    conn.close()
    return row


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
# RISK SCORING ENGINE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def calculate_risk_score_rating(likelihood, impact):
    """
    Standard likelihood x impact risk matrix calculation.
    Both likelihood and impact are rated 1-5.
    Score = likelihood x impact, range 1-25.

    Rating bands (standard GRC risk matrix):
    1-4   = Low
    5-9   = Medium
    10-14 = High
    15-25 = Critical
    """
    score = likelihood * impact
    if score >= 15:
        rating = "Critical"
    elif score >= 10:
        rating = "High"
    elif score >= 5:
        rating = "Medium"
    else:
        rating = "Low"
    return score, rating


def get_all_risks():
    """Fetch all risks, highest score first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM risks ORDER BY risk_score DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_risk_by_id(risk_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM risks WHERE id = ?", (risk_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def create_risk(title, description, source_type, source_ref, likelihood, impact,
                 owner, identified_date):
    """Add a new risk to the register. Score and rating are auto-calculated."""
    score, rating = calculate_risk_score_rating(likelihood, impact)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO risks (
            title, description, source_type, source_ref,
            likelihood, impact, risk_score, risk_rating,
            status, owner, identified_date, reviewed_date, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        title, description, source_type, source_ref,
        likelihood, impact, score, rating,
        "Open", owner, identified_date, None,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def update_risk(risk_id, likelihood, impact, status, owner):
    """Update an existing risk's scoring, status, or owner."""
    score, rating = calculate_risk_score_rating(likelihood, impact)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE risks SET
            likelihood = ?, impact = ?, risk_score = ?, risk_rating = ?,
            status = ?, owner = ?, reviewed_date = ?
        WHERE id = ?
    """, (
        likelihood, impact, score, rating, status, owner,
        datetime.date.today().strftime("%Y-%m-%d"), risk_id
    ))
    conn.commit()
    conn.close()


def delete_risk(risk_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM risks WHERE id = ?", (risk_id,))
    conn.commit()
    conn.close()


def get_existing_risk_refs():
    """Return the set of source_ref values already in the risk register, to avoid duplicate auto-generation."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT source_ref FROM risks WHERE source_ref IS NOT NULL")
    rows = cursor.fetchall()
    conn.close()
    return {row["source_ref"] for row in rows}


def auto_generate_risks_from_controls():
    """
    Scan all Non-Compliant controls and auto-generate risk entries for any
    that don't already have a linked risk. Likelihood/impact are pre-set
    based on the framework the control belongs to, admin can adjust after.
    Returns the number of new risks created.
    """
    existing_refs = get_existing_risk_refs()
    controls = get_all_controls()
    created = 0
    for c in controls:
        if c["status"] != "Non-Compliant":
            continue
        ref = f"CONTROL:{c['control_id']}"
        if ref in existing_refs:
            continue
        # Default scoring: non-compliant controls get moderate-high likelihood,
        # impact scaled by whether it touches regulatory frameworks (NDPA/GDPR/PCI)
        likelihood = 4  # non-compliance is an active, ongoing gap - likely to be found
        impact = 4
        if c["ndpa"] not in (None, "N/A", "") or c["gdpr"] not in (None, "N/A", ""):
            impact = 5  # regulatory exposure carries higher impact
        create_risk(
            title=f"Non-compliance: {c['control_id']}",
            description=c["nist_description"],
            source_type="Control",
            source_ref=ref,
            likelihood=likelihood,
            impact=impact,
            owner="Unassigned",
            identified_date=datetime.date.today().strftime("%Y-%m-%d")
        )
        created += 1
    return created


def auto_generate_risks_from_vulnerabilities():
    """
    Scan all Critical and High risk vulnerabilities that are still Open or
    In Progress, and auto-generate risk entries for any not already linked.
    Likelihood/impact derived from CVSS score.
    Returns the number of new risks created.
    """
    existing_refs = get_existing_risk_refs()
    vulns = get_all_vulnerabilities()
    created = 0
    for v in vulns:
        if v["risk_rating"] not in ("Critical", "High"):
            continue
        if v["status"] not in ("Open", "In Progress"):
            continue
        ref = f"VULN:{v['id']}"
        if ref in existing_refs:
            continue
        # CVSS 9-10 -> likelihood 5, CVSS 7-8.9 -> likelihood 4
        likelihood = 5 if v["risk_rating"] == "Critical" else 4
        impact = 5 if v["risk_rating"] == "Critical" else 4
        create_risk(
            title=f"Vulnerability: {v['cve_id'] or 'Unidentified CVE'} on {v['asset_name']}",
            description=v["description"] or "No description provided.",
            source_type="Vulnerability",
            source_ref=ref,
            likelihood=likelihood,
            impact=impact,
            owner=v["assigned_to"] or "Unassigned",
            identified_date=v["identified_date"] or datetime.date.today().strftime("%Y-%m-%d")
        )
        created += 1
    return created


def get_risk_summary():
    """Count risks by rating for summary cards."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT risk_rating, COUNT(*) as count FROM risks GROUP BY risk_rating")
    rows = cursor.fetchall()
    conn.close()
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in rows:
        summary[row["risk_rating"]] = row["count"]
    return summary


def get_risk_status_summary():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status, COUNT(*) as count FROM risks GROUP BY status")
    rows = cursor.fetchall()
    conn.close()
    summary = {"Open": 0, "Mitigating": 0, "Closed": 0, "Accepted": 0}
    for row in rows:
        summary[row["status"]] = row["count"]
    return summary


def get_heatmap_matrix():
    """
    Build a 5x5 grid counting how many risks fall into each
    likelihood/impact combination. Used to render the heat map.
    Returns a dict keyed by (likelihood, impact) tuple -> count.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT likelihood, impact, COUNT(*) as count FROM risks GROUP BY likelihood, impact")
    rows = cursor.fetchall()
    conn.close()
    matrix = {}
    for row in rows:
        matrix[(row["likelihood"], row["impact"])] = row["count"]
    return matrix


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


def get_admin_emails():
    """
    Fetch email addresses of all active admin users.
    Used to send alert notifications (Critical vuln, Non-Compliant control, etc).
    Skips any admin with no email set.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE role = 'admin' AND is_active = 1 AND email IS NOT NULL AND email != ''")
    rows = cursor.fetchall()
    conn.close()
    return [row["email"] for row in rows]


def verify_password(username, password):
    user = get_user_by_username(username)
    if not user:
        return None, "invalid"
    if not check_password_hash(user["password_hash"], password):
        return None, "invalid"
    if not user["is_active"]:
        return None, "inactive"
    return user, "ok"


def register_user(username, email, password):
    if get_user_by_username(username):
        return False, "Username already exists."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not email or "@" not in email:
        return False, "A valid email address is required."
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username, email, generate_password_hash(password), "viewer", 0,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        return True, "ok"
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def create_user_by_admin(username, email, password, role):
    if get_user_by_username(username):
        return False, "Username already exists."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username, email, generate_password_hash(password), role, 1,
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

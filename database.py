# database.py
# Updated: added risks table for the Risk Scoring Engine (likelihood x impact matrix).

import sqlite3
import datetime
import secrets
import hashlib
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
            status           TEXT DEFAULT 'Not Assessed',
            tier             TEXT DEFAULT 'core'
        )
    """)

    # Migration: add tier column if the table already existed without it
    cursor.execute("PRAGMA table_info(controls)")
    existing_control_columns = [row["name"] for row in cursor.fetchall()]
    if "tier" not in existing_control_columns:
        cursor.execute("ALTER TABLE controls ADD COLUMN tier TEXT DEFAULT 'core'")

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

    # API keys for external tool integration (SIEM, EDR, and similar).
    # Each admin can generate their own key. Keys are stored hashed,
    # only the prefix is kept in plain text for display/identification.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            key_hash     TEXT NOT NULL,
            key_prefix   TEXT NOT NULL,
            label        TEXT,
            is_active    INTEGER DEFAULT 1,
            last_used_at TEXT,
            created_at   TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Incoming events log: every event received via the API, successful or not.
    # Kept separate from session_log since these come from external systems,
    # not from logged-in user actions.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incoming_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            source       TEXT,
            event_type   TEXT,
            severity     TEXT,
            title        TEXT,
            payload_raw  TEXT,
            status       TEXT,
            result_detail TEXT,
            received_at  TEXT
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
                    status, tier
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                details["status"],
                details.get("tier", "core")
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

def get_all_controls(tier=None):
    """
    Fetch controls, optionally filtered by tier.
    tier=None or 'full' -> everything
    tier='core' -> only the curated baseline set (currently the original 39)
    """
    conn = get_connection()
    cursor = conn.cursor()
    if tier == "core":
        cursor.execute("SELECT * FROM controls WHERE tier = 'core' ORDER BY nist_function, control_id")
    else:
        cursor.execute("SELECT * FROM controls ORDER BY nist_function, control_id")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_priority_items():
    """
    Cross-table Priority view: pulls together everything that needs
    attention right now, regardless of which module it lives in.
    - Non-Compliant controls
    - Open/In Progress vulnerabilities rated Critical or High
    - Open/Mitigating risks rated Critical or High
    Returns a single list of dicts, each tagged with its source type,
    so the dashboard can render one unified "needs attention" table.
    """
    conn = get_connection()
    cursor = conn.cursor()
    items = []

    cursor.execute("SELECT * FROM controls WHERE status = 'Non-Compliant' ORDER BY control_id")
    for row in cursor.fetchall():
        items.append({
            "source_type": "Control",
            "title": row["control_id"],
            "description": row["nist_description"],
            "severity": "Non-Compliant",
            "link": "/",
        })

    cursor.execute("""
        SELECT vulnerabilities.*, assets.name AS asset_name
        FROM vulnerabilities
        JOIN assets ON vulnerabilities.asset_id = assets.id
        WHERE vulnerabilities.risk_rating IN ('Critical', 'High')
        AND vulnerabilities.status IN ('Open', 'In Progress')
        ORDER BY vulnerabilities.cvss_score DESC
    """)
    for row in cursor.fetchall():
        items.append({
            "source_type": "Vulnerability",
            "title": row["cve_id"] or f"Unidentified CVE on {row['asset_name']}",
            "description": row["description"] or "No description provided.",
            "severity": row["risk_rating"],
            "link": "/vulnerabilities",
        })

    cursor.execute("""
        SELECT * FROM risks
        WHERE risk_rating IN ('Critical', 'High')
        AND status IN ('Open', 'Mitigating')
        ORDER BY risk_score DESC
    """)
    for row in cursor.fetchall():
        items.append({
            "source_type": "Risk",
            "title": row["title"],
            "description": row["description"] or "No description provided.",
            "severity": row["risk_rating"],
            "link": "/risks",
        })

    conn.close()
    return items


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


# ─────────────────────────────────────────────────────────────────────────────
# API KEY MANAGEMENT (for SIEM/EDR and other external tool integration)
# ─────────────────────────────────────────────────────────────────────────────

def generate_api_key(user_id, label):
    """
    Generate a new API key for a user. The full key is returned ONCE here
    and never stored in plain text or retrievable again, only its hash is
    kept for verification, standard practice for API keys (same principle
    as password hashing).

    Returns the full key string (e.g. 'auditra_live_xxxxxxxxxxxx') so the
    caller can display it to the admin exactly once.
    """
    raw_secret = secrets.token_hex(24)          # 48 hex characters of randomness
    full_key   = f"auditra_live_{raw_secret}"
    key_hash   = hashlib.sha256(full_key.encode()).hexdigest()
    key_prefix = full_key[:20]                   # shown in the UI for identification, not the secret itself

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO api_keys (user_id, key_hash, key_prefix, label, is_active, created_at)
        VALUES (?, ?, ?, ?, 1, ?)
    """, (
        user_id, key_hash, key_prefix, label,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()
    return full_key


def get_api_keys_for_user(user_id):
    """List all API keys belonging to a user, without exposing the actual secret."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def revoke_api_key(key_id, user_id):
    """
    Deactivate a key. Scoped to user_id so a user can only revoke their own keys,
    prevents an admin from accidentally or maliciously revoking someone else's.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?",
        (key_id, user_id)
    )
    conn.commit()
    conn.close()


def verify_api_key(provided_key):
    """
    Check an incoming API key against stored hashes.
    Returns the associated user row if valid and active, otherwise None.
    Updates last_used_at on successful verification.
    """
    if not provided_key or not provided_key.startswith("auditra_live_"):
        return None

    key_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT api_keys.*, users.username, users.role
        FROM api_keys
        JOIN users ON api_keys.user_id = users.id
        WHERE api_keys.key_hash = ? AND api_keys.is_active = 1
    """, (key_hash,))
    row = cursor.fetchone()

    if row:
        cursor.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), row["id"])
        )
        conn.commit()

    conn.close()
    return row


# ─────────────────────────────────────────────────────────────────────────────
# INCOMING EVENTS (SIEM/EDR groundwork)
# ─────────────────────────────────────────────────────────────────────────────

def log_incoming_event(source, event_type, severity, title, payload_raw, status, result_detail):
    """Record every incoming API event, successful or rejected, for auditability."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO incoming_events (source, event_type, severity, title, payload_raw, status, result_detail, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        source, event_type, severity, title, payload_raw, status, result_detail,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def get_incoming_events(limit=100):
    """Fetch the most recent incoming events, newest first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incoming_events ORDER BY received_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def process_incoming_event(event_type, severity, title, description, asset_name, cvss_score, source):
    """
    Convert a validated incoming event into an actual Auditra record.
    event_type='vulnerability' creates/updates an asset and logs a vulnerability.
    event_type='risk' creates a manual-style risk entry.
    Returns (success: bool, message: str).
    """
    severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
    normalized_severity = severity_map.get((severity or "").lower(), "Medium")

    if event_type == "vulnerability":
        # Find or create the asset by name
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM assets WHERE name = ?", (asset_name,))
        row = cursor.fetchone()
        if row:
            asset_id = row["id"]
        else:
            cursor.execute("""
                INSERT INTO assets (name, category, description, owner, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                asset_name or "Unknown Asset (from integration)", "Server / Infrastructure",
                f"Auto-created from {source} integration", "Unassigned",
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            asset_id = cursor.lastrowid
        conn.commit()
        conn.close()

        score = cvss_score if cvss_score is not None else {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.0}[normalized_severity]
        create_vulnerability(
            asset_id=asset_id, cve_id=title, cvss_score=score,
            description=description or f"Received via {source} integration",
            affected_system=asset_name, identified_date=datetime.date.today().strftime("%Y-%m-%d"),
            assigned_to="Unassigned"
        )
        return True, f"Vulnerability created on asset '{asset_name}'."

    elif event_type == "risk":
        likelihood_map = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}
        impact_map     = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}
        create_risk(
            title=title or f"Risk from {source}",
            description=description or f"Received via {source} integration",
            source_type="Integration", source_ref=f"{source}:{title}",
            likelihood=likelihood_map[normalized_severity], impact=impact_map[normalized_severity],
            owner="Unassigned", identified_date=datetime.date.today().strftime("%Y-%m-%d")
        )
        return True, "Risk entry created."

    else:
        return False, f"Unknown event_type '{event_type}'. Must be 'vulnerability' or 'risk'."

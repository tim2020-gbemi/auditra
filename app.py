# app.py
# Updated: added vulnerability tracker routes.

import datetime
import csv
import io
from flask import Flask, render_template, request, redirect, url_for, session, make_response
from xhtml2pdf import pisa
from database import (
    init_db, get_connection, get_all_controls, update_status, get_summary, get_audit_log,
    verify_password, register_user, create_user_by_admin, get_all_users,
    activate_user, deactivate_user, update_user_role, change_password,
    admin_reset_password, delete_user, get_user_by_id,
    log_activity, get_session_log, get_session_stats,
    get_all_assets, get_asset_by_id, create_asset, delete_asset,
    get_all_vulnerabilities, get_vulnerability_by_id, create_vulnerability,
    update_vulnerability_status, delete_vulnerability,
    get_vulnerability_summary, get_vulnerability_status_summary
)

app = Flask(__name__)
app.secret_key = "auditra-production-secret-key-x9k2mP7qL4nR"

init_db()


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def logged_in():
    return "username" in session

def is_admin():
    return session.get("role") == "admin"

def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user, status = verify_password(username, password)
        if status == "ok":
            session["username"] = user["username"]
            session["role"]     = user["role"]
            session["user_id"]  = user["id"]
            log_activity(username, "LOGIN", "Successful login", get_ip())
            return redirect(url_for("dashboard"))
        elif status == "inactive":
            log_activity(username, "LOGIN_FAILED", "Account pending approval", get_ip())
            error = "Your account is pending admin approval. Please check back later."
        else:
            log_activity(username or "unknown", "LOGIN_FAILED", "Invalid credentials", get_ip())
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    if logged_in():
        log_activity(session["username"], "LOGOUT", "User logged out", get_ip())
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if logged_in():
        return redirect(url_for("dashboard"))
    error   = None
    success = None
    if request.method == "POST":
        username         = request.form.get("username", "").strip()
        password         = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        if not username or not password:
            error = "Username and password are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            ok, message = register_user(username, password)
            if ok:
                log_activity(username, "REGISTER", "Self-registration submitted, pending approval", get_ip())
                success = "Account created. Please wait for admin approval before logging in."
            else:
                error = message
    return render_template("register.html", error=error, success=success)


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "PAGE_VIEW", "Viewed compliance dashboard", get_ip())
    controls  = get_all_controls()
    summary   = get_summary()
    audit_log = get_audit_log()
    total     = len(controls)
    score     = round((summary["Compliant"] / total) * 100) if total > 0 else 0
    return render_template(
        "dashboard.html",
        controls=controls, summary=summary, audit_log=audit_log,
        score=score, total=total,
        username=session["username"], role=session["role"]
    )


@app.route("/update", methods=["POST"])
def update():
    if not logged_in():
        return redirect(url_for("login"))
    if not is_admin():
        return redirect(url_for("dashboard"))
    control_id = request.form.get("control_id")
    new_status  = request.form.get("status")
    update_status(control_id, new_status, session["username"])
    log_activity(session["username"], "STATUS_UPDATE", f"Updated {control_id} to {new_status}", get_ip())
    return redirect(url_for("dashboard"))


# ─────────────────────────────────────────────────────────────────────────────
# COMPLIANCE EXPORTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/pdf")
def export_pdf():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "EXPORT", "Downloaded PDF compliance report", get_ip())
    controls  = get_all_controls()
    summary   = get_summary()
    total     = len(controls)
    score     = round((summary["Compliant"] / total) * 100) if total > 0 else 0
    date      = datetime.date.today().strftime("%Y-%m-%d")
    html_string = render_template(
        "report.html", controls=controls, summary=summary,
        score=score, total=total, date=date, username=session["username"]
    )
    pdf_buffer = io.BytesIO()
    pisa.CreatePDF(html_string, dest=pdf_buffer)
    response = make_response(pdf_buffer.getvalue())
    response.headers["Content-Type"]        = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=auditra_report_{date}.pdf"
    return response


@app.route("/csv")
def export_csv():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "EXPORT", "Downloaded CSV compliance report", get_ip())
    controls = get_all_controls()
    date     = datetime.date.today().strftime("%Y-%m-%d")
    output   = io.StringIO()
    writer   = csv.writer(output)
    writer.writerow([
        "Control ID", "NIST Function", "NIST Description", "ISO 27001", "ISO Detail",
        "SOC 2 TSC", "SOC 2 Detail", "PCI-DSS", "PCI Detail",
        "NDPA/GAID", "NDPA Detail", "GDPR", "GDPR Detail", "Status"
    ])
    for row in controls:
        writer.writerow([
            row["control_id"], row["nist_function"], row["nist_description"],
            row["iso_27001"], row["iso_description"], row["soc2_tsc"], row["soc2_description"],
            row["pci_dss"], row["pci_description"], row["ndpa"], row["ndpa_description"],
            row["gdpr"], row["gdpr_description"], row["status"]
        ])
    response = make_response(output.getvalue())
    response.headers["Content-Type"]        = "text/csv"
    response.headers["Content-Disposition"] = f"attachment; filename=auditra_report_{date}.csv"
    return response


@app.route("/html-export")
def export_html():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "EXPORT", "Downloaded HTML compliance report", get_ip())
    controls  = get_all_controls()
    summary   = get_summary()
    total     = len(controls)
    score     = round((summary["Compliant"] / total) * 100) if total > 0 else 0
    date      = datetime.date.today().strftime("%Y-%m-%d")
    html_string = render_template(
        "report_html.html", controls=controls, summary=summary,
        score=score, total=total, date=date, username=session["username"]
    )
    response = make_response(html_string)
    response.headers["Content-Type"]        = "text/html"
    response.headers["Content-Disposition"] = f"attachment; filename=auditra_report_{date}.html"
    return response


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY TRACKER
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/vulnerabilities")
def vulnerabilities():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "PAGE_VIEW", "Viewed vulnerability dashboard", get_ip())
    vulns         = get_all_vulnerabilities()
    assets        = get_all_assets()
    risk_summary  = get_vulnerability_summary()
    status_summary = get_vulnerability_status_summary()
    total_vulns   = len(vulns)
    open_count    = status_summary["Open"] + status_summary["In Progress"]
    return render_template(
        "vulnerabilities.html",
        vulns=vulns, assets=assets,
        risk_summary=risk_summary, status_summary=status_summary,
        total_vulns=total_vulns, open_count=open_count,
        username=session["username"], role=session["role"]
    )


@app.route("/assets/create", methods=["POST"])
def create_asset_route():
    if not logged_in() or not is_admin():
        return redirect(url_for("vulnerabilities"))
    name        = request.form.get("name", "").strip()
    category    = request.form.get("category", "").strip()
    description = request.form.get("description", "").strip()
    owner       = request.form.get("owner", "").strip()
    if name and category:
        asset_id = create_asset(name, category, description, owner)
        log_activity(session["username"], "ASSET_CREATED", f"Created asset: {name} ({category})", get_ip())
    return redirect(url_for("vulnerabilities"))


@app.route("/assets/delete/<int:asset_id>")
def delete_asset_route(asset_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("vulnerabilities"))
    asset = get_asset_by_id(asset_id)
    if asset:
        log_activity(session["username"], "ASSET_DELETED", f"Deleted asset: {asset['name']}", get_ip())
    delete_asset(asset_id)
    return redirect(url_for("vulnerabilities"))


@app.route("/vulnerabilities/create", methods=["POST"])
def create_vulnerability_route():
    if not logged_in() or not is_admin():
        return redirect(url_for("vulnerabilities"))
    asset_id        = request.form.get("asset_id")
    cve_id          = request.form.get("cve_id", "").strip()
    cvss_score_raw  = request.form.get("cvss_score", "").strip()
    description     = request.form.get("description", "").strip()
    affected_system = request.form.get("affected_system", "").strip()
    identified_date = request.form.get("identified_date", "").strip()
    assigned_to     = request.form.get("assigned_to", "").strip()

    cvss_score = None
    if cvss_score_raw:
        try:
            cvss_score = float(cvss_score_raw)
        except ValueError:
            cvss_score = None

    if asset_id:
        create_vulnerability(
            int(asset_id), cve_id, cvss_score, description,
            affected_system, identified_date, assigned_to
        )
        log_activity(
            session["username"], "VULN_CREATED",
            f"Logged vulnerability: {cve_id or 'No CVE ID'} on asset ID {asset_id}", get_ip()
        )
    return redirect(url_for("vulnerabilities"))


@app.route("/vulnerabilities/update-status/<int:vuln_id>", methods=["POST"])
def update_vulnerability_status_route(vuln_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("vulnerabilities"))
    new_status = request.form.get("status", "").strip()
    update_vulnerability_status(vuln_id, new_status)
    log_activity(session["username"], "VULN_STATUS_UPDATE", f"Updated vuln #{vuln_id} to {new_status}", get_ip())
    return redirect(url_for("vulnerabilities"))


@app.route("/vulnerabilities/delete/<int:vuln_id>")
def delete_vulnerability_route(vuln_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("vulnerabilities"))
    delete_vulnerability(vuln_id)
    log_activity(session["username"], "VULN_DELETED", f"Deleted vulnerability #{vuln_id}", get_ip())
    return redirect(url_for("vulnerabilities"))


@app.route("/vulnerabilities/pdf")
def export_vuln_pdf():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "EXPORT", "Downloaded PDF vulnerability report", get_ip())
    vulns          = get_all_vulnerabilities()
    risk_summary   = get_vulnerability_summary()
    status_summary = get_vulnerability_status_summary()
    total_vulns    = len(vulns)
    date           = datetime.date.today().strftime("%Y-%m-%d")
    html_string = render_template(
        "vuln_report.html",
        vulns=vulns, risk_summary=risk_summary, status_summary=status_summary,
        total_vulns=total_vulns, date=date, username=session["username"]
    )
    pdf_buffer = io.BytesIO()
    pisa.CreatePDF(html_string, dest=pdf_buffer)
    response = make_response(pdf_buffer.getvalue())
    response.headers["Content-Type"]        = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=auditra_vuln_report_{date}.pdf"
    return response


@app.route("/vulnerabilities/csv")
def export_vuln_csv():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "EXPORT", "Downloaded CSV vulnerability report", get_ip())
    vulns  = get_all_vulnerabilities()
    date   = datetime.date.today().strftime("%Y-%m-%d")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Asset", "Category", "CVE ID", "CVSS Score", "Risk Rating",
        "Description", "Affected System", "Status",
        "Identified Date", "Resolved Date", "Assigned To"
    ])
    for v in vulns:
        writer.writerow([
            v["asset_name"], v["asset_category"], v["cve_id"], v["cvss_score"],
            v["risk_rating"], v["description"], v["affected_system"], v["status"],
            v["identified_date"], v["resolved_date"], v["assigned_to"]
        ])
    response = make_response(output.getvalue())
    response.headers["Content-Type"]        = "text/csv"
    response.headers["Content-Disposition"] = f"attachment; filename=auditra_vuln_report_{date}.csv"
    return response


# ─────────────────────────────────────────────────────────────────────────────
# PASSWORD CHANGE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/change-password", methods=["GET", "POST"])
def change_password_route():
    if not logged_in():
        return redirect(url_for("login"))
    log_activity(session["username"], "PAGE_VIEW", "Viewed change password page", get_ip())
    error   = None
    success = None
    if request.method == "POST":
        current = request.form.get("current_password", "").strip()
        new     = request.form.get("new_password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()
        if new != confirm:
            error = "New passwords do not match."
        else:
            ok, message = change_password(session["user_id"], current, new)
            if ok:
                log_activity(session["username"], "PASSWORD_CHANGE", "User changed their password", get_ip())
                success = message
            else:
                error = message
    return render_template(
        "change_password.html", error=error, success=success,
        username=session["username"], role=session["role"]
    )


# ─────────────────────────────────────────────────────────────────────────────
# USER MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/users")
def users():
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    log_activity(session["username"], "PAGE_VIEW", "Viewed user management page", get_ip())
    all_users = get_all_users()
    return render_template("users.html", users=all_users, username=session["username"], role=session["role"])


@app.route("/users/create", methods=["POST"])
def create_user():
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role     = request.form.get("role", "viewer").strip()
    ok, message = create_user_by_admin(username, password, role)
    if ok:
        log_activity(session["username"], "USER_CREATED", f"Created user: {username} ({role})", get_ip())
    all_users = get_all_users()
    return render_template(
        "users.html", users=all_users, username=session["username"], role=session["role"],
        error=None if ok else message, success="User created successfully." if ok else None
    )


@app.route("/users/activate/<int:user_id>")
def activate(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    user = get_user_by_id(user_id)
    if user:
        log_activity(session["username"], "USER_ACTIVATED", f"Activated user: {user['username']}", get_ip())
    activate_user(user_id)
    return redirect(url_for("users"))


@app.route("/users/deactivate/<int:user_id>")
def deactivate(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    if user_id == session["user_id"]:
        return redirect(url_for("users"))
    user = get_user_by_id(user_id)
    if user:
        log_activity(session["username"], "USER_DEACTIVATED", f"Deactivated user: {user['username']}", get_ip())
    deactivate_user(user_id)
    return redirect(url_for("users"))


@app.route("/users/role/<int:user_id>", methods=["POST"])
def change_role(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    new_role = request.form.get("role", "viewer")
    user = get_user_by_id(user_id)
    if user:
        log_activity(session["username"], "ROLE_CHANGE", f"Changed {user['username']} role to {new_role}", get_ip())
    update_user_role(user_id, new_role)
    return redirect(url_for("users"))


@app.route("/users/reset-password/<int:user_id>", methods=["POST"])
def reset_user_password(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    new_password = request.form.get("new_password", "").strip()
    ok, message  = admin_reset_password(user_id, new_password)
    user = get_user_by_id(user_id)
    if ok and user:
        log_activity(session["username"], "PASSWORD_RESET", f"Reset password for: {user['username']}", get_ip())
    all_users = get_all_users()
    return render_template(
        "users.html", users=all_users, username=session["username"], role=session["role"],
        error=None if ok else message, success=message if ok else None
    )


@app.route("/users/delete/<int:user_id>")
def remove_user(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    if user_id == session["user_id"]:
        return redirect(url_for("users"))
    user = get_user_by_id(user_id)
    if user:
        log_activity(session["username"], "USER_DELETED", f"Deleted user: {user['username']}", get_ip())
    delete_user(user_id)
    return redirect(url_for("users"))


# ─────────────────────────────────────────────────────────────────────────────
# DEVELOPER LOG
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/devlog")
def devlog():
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    log_activity(session["username"], "PAGE_VIEW", "Viewed developer activity log", get_ip())
    logs  = get_session_log(limit=1000)
    stats = get_session_stats()
    return render_template("devlog.html", logs=logs, stats=stats, username=session["username"], role=session["role"])


@app.route("/devlog/clear", methods=["POST"])
def clear_devlog():
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM session_log")
    conn.commit()
    conn.close()
    log_activity(session["username"], "LOG_CLEARED", "Session log cleared by admin", get_ip())
    return redirect(url_for("devlog"))


if __name__ == "__main__":
    app.run(debug=True)

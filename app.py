# app.py
# Updated: added registration, user management, and password change routes.

import datetime
from flask import Flask, render_template, request, redirect, url_for, session, make_response
from xhtml2pdf import pisa
import io
from database import (
    init_db, get_all_controls, update_status, get_summary, get_audit_log,
    verify_password, register_user, create_user_by_admin, get_all_users,
    activate_user, deactivate_user, update_user_role, change_password,
    admin_reset_password, delete_user, get_user_by_id
)

app = Flask(__name__)
app.secret_key = "grc-toolkit-secret-key-change-in-production"

init_db()


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def logged_in():
    return "username" in session

def is_admin():
    return session.get("role") == "admin"


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
            return redirect(url_for("dashboard"))
        elif status == "inactive":
            error = "Your account is pending admin approval. Please check back later."
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    # Already logged in users don't need to register
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
    controls  = get_all_controls()
    summary   = get_summary()
    audit_log = get_audit_log()
    total     = len(controls)
    score     = round((summary["Compliant"] / total) * 100) if total > 0 else 0
    return render_template(
        "dashboard.html",
        controls=controls,
        summary=summary,
        audit_log=audit_log,
        score=score,
        total=total,
        username=session["username"],
        role=session["role"]
    )


@app.route("/update", methods=["POST"])
def update():
    if not logged_in():
        return redirect(url_for("login"))
    if not is_admin():
        return redirect(url_for("dashboard"))
    update_status(
        request.form.get("control_id"),
        request.form.get("status"),
        session["username"]
    )
    return redirect(url_for("dashboard"))


# ─────────────────────────────────────────────────────────────────────────────
# PDF EXPORT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/pdf")
def export_pdf():
    if not logged_in():
        return redirect(url_for("login"))
    controls  = get_all_controls()
    summary   = get_summary()
    audit_log = get_audit_log()
    total     = len(controls)
    score     = round((summary["Compliant"] / total) * 100) if total > 0 else 0
    date      = datetime.date.today().strftime("%Y-%m-%d")
    html_string = render_template(
        "report.html",
        controls=controls, summary=summary, audit_log=audit_log,
        score=score, total=total, date=date, username=session["username"]
    )
    pdf_buffer = io.BytesIO()
    pisa.CreatePDF(html_string, dest=pdf_buffer)
    pdf_bytes = pdf_buffer.getvalue()
    response = make_response(pdf_bytes)
    response.headers["Content-Type"]        = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=compliance_report_{date}.pdf"
    return response


# ─────────────────────────────────────────────────────────────────────────────
# PASSWORD CHANGE (any logged-in user)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/change-password", methods=["GET", "POST"])
def change_password_route():
    if not logged_in():
        return redirect(url_for("login"))
    error   = None
    success = None
    if request.method == "POST":
        current  = request.form.get("current_password", "").strip()
        new      = request.form.get("new_password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()
        if new != confirm:
            error = "New passwords do not match."
        else:
            ok, message = change_password(session["user_id"], current, new)
            if ok:
                success = message
            else:
                error = message
    return render_template(
        "change_password.html",
        error=error, success=success,
        username=session["username"], role=session["role"]
    )


# ─────────────────────────────────────────────────────────────────────────────
# USER MANAGEMENT (admin only)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/users")
def users():
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    all_users = get_all_users()
    return render_template(
        "users.html",
        users=all_users,
        username=session["username"],
        role=session["role"]
    )


@app.route("/users/create", methods=["POST"])
def create_user():
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role     = request.form.get("role", "viewer").strip()
    ok, message = create_user_by_admin(username, password, role)
    all_users = get_all_users()
    error   = None if ok else message
    success = "User created successfully." if ok else None
    return render_template(
        "users.html",
        users=all_users,
        username=session["username"],
        role=session["role"],
        error=error,
        success=success
    )


@app.route("/users/activate/<int:user_id>")
def activate(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    activate_user(user_id)
    return redirect(url_for("users"))


@app.route("/users/deactivate/<int:user_id>")
def deactivate(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    # Prevent admin from deactivating their own account
    if user_id == session["user_id"]:
        return redirect(url_for("users"))
    deactivate_user(user_id)
    return redirect(url_for("users"))


@app.route("/users/role/<int:user_id>", methods=["POST"])
def change_role(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    new_role = request.form.get("role", "viewer")
    update_user_role(user_id, new_role)
    return redirect(url_for("users"))


@app.route("/users/reset-password/<int:user_id>", methods=["POST"])
def reset_user_password(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    new_password = request.form.get("new_password", "").strip()
    ok, message  = admin_reset_password(user_id, new_password)
    all_users    = get_all_users()
    return render_template(
        "users.html",
        users=all_users,
        username=session["username"],
        role=session["role"],
        error=None if ok else message,
        success=message if ok else None
    )


@app.route("/users/delete/<int:user_id>")
def remove_user(user_id):
    if not logged_in() or not is_admin():
        return redirect(url_for("dashboard"))
    # Prevent admin from deleting their own account
    if user_id == session["user_id"]:
        return redirect(url_for("users"))
    delete_user(user_id)
    return redirect(url_for("users"))


if __name__ == "__main__":
    app.run(debug=True)

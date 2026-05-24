# Auditra

Compliance management platform for GRC engineers and analysts.
Built to reduce manual effort on control mapping, assessment tracking,
and audit reporting across six frameworks simultaneously.

Currently in active development. Phase 1 complete.

---

## What It Does

- Maps 39 controls across six compliance frameworks simultaneously
- Tracks assessment status per control with full audit trail
- Role-based access control (Admin and Viewer roles)
- User management with self-registration and admin approval
- Exports audit-ready reports in PDF, CSV, and HTML formats
- Framework filter tabs to isolate controls by standard
- Live compliance score updated in real time

---

## Frameworks Covered

| Framework | Version | Notes |
|---|---|---|
| NIST CSF | 2.0 | Core control structure |
| ISO 27001 | 2022 | International security standard |
| SOC 2 | Trust Services Criteria | Service organization controls |
| PCI-DSS | v4.0.1 | Payment card security |
| NDPA + GAID | 2023 + 2025 | Nigeria Data Protection Act + General Application and Implementation Directive |
| GDPR | 2018 (enforced) | EU General Data Protection Regulation |

> NDPR 2019 is no longer in effect. Auditra maps to the current Nigerian
> data protection instruments: NDPA 2023 and GAID 2025, effective
> September 19, 2025.

> GDPR coverage is included for Nigerian businesses processing personal
> data of EU citizens, a dual compliance obligation with no existing
> tool mapping both frameworks simultaneously.

---

## Project Structure

```
auditra/
├── compliance_mapper.py   # Core control database (39 controls, 6 frameworks)
├── app.py                 # Flask web server with auth and routes
├── database.py            # SQLite database layer with audit logging
├── templates/
│   ├── login.html         # Login page
│   ├── register.html      # Self-registration page
│   ├── dashboard.html     # Main compliance dashboard
│   ├── users.html         # Admin user management
│   ├── change_password.html # Password change page
│   ├── report.html        # PDF report template
│   └── report_html.html   # HTML export template
└── static/                # Static assets
```

---

## Features

### Compliance Dashboard
- Live compliance score based on assessed controls
- Summary cards: Compliant, Partial, Non-Compliant, Not Assessed
- Framework filter tabs: All, NIST CSF, PCI-DSS, NDPA/GAID, GDPR
- Full controls table with all six framework mappings

### Authentication & Roles
- Login required to access the dashboard
- Admin: can update control statuses and manage users
- Viewer: read-only access
- Self-registration with admin approval workflow
- All status changes logged with username and timestamp

### Reports
- PDF export for audit delivery (landscape, professional layout)
- CSV export for spreadsheet workflows
- HTML export for browser-viewable sharing

### Audit Trail
- Every status change recorded: control, old status, new status, who, when
- Visible on the dashboard in real time

### User Management
- Admin creates accounts directly (active immediately)
- Self-registration page (pending admin approval)
- Role assignment and changes (Admin or Viewer)
- Password reset by admin for any user
- Users can change their own password

---

## Run Locally

```bash
pip install flask werkzeug xhtml2pdf
python app.py
```

Open: http://localhost:5000

Default admin credentials (change after first login):
- Username: `admin`
- Password: `admin123`

---

## Controls Coverage

| Category | Count |
|---|---|
| NIST CSF core controls | 13 |
| PCI-DSS specific | 4 |
| NDPA + GAID specific | 7 |
| GDPR specific | 15 |
| **Total** | **39** |

---

## Competitive Position

| Platform | NIST | ISO 27001 | SOC 2 | PCI-DSS | NDPA/GAID | GDPR | Price/yr |
|---|---|---|---|---|---|---|---|
| Auditra | Yes | Yes | Yes | Yes | Yes | Yes | TBD |
| Vanta | Yes | Yes | Yes | Yes | No | Partial | $15k+ |
| Drata | Yes | Yes | Yes | Yes | No | Partial | $15k+ |
| Tugboat Logic | Yes | Yes | Yes | No | No | Partial | $10k+ |

> Auditra is the only tool with native NDPA 2023 and GAID 2025 support.

---

## Roadmap

- [x] Core compliance mapper (CLI)
- [x] Flask web app
- [x] SQLite persistent database
- [x] User authentication and roles
- [x] User management and self-registration
- [x] PDF, CSV, and HTML export
- [x] Multi-framework support (NDPA 2023 + GAID 2025 + GDPR)
- [x] Framework filter tabs
- [x] Audit trail
- [ ] Deploy to DigitalOcean (public URL)
- [ ] Vulnerability tracker with CVE mapping
- [ ] Risk scoring engine
- [ ] Email-based notifications
- [ ] Multi-tenant architecture (Phase 3)
- [ ] Paystack subscription billing (Phase 3)
- [ ] Portfolio site

---

## About

Built by a GRC engineer and cybersecurity analyst based in Lagos, Nigeria.
Focus: reducing the manual overhead of compliance mapping and audit prep
for organizations operating under Nigerian and international data protection
and security frameworks.

Tools: Python 3, Flask, SQLite, xhtml2pdf, GitHub Copilot, VS Code.

---

*Auditra | Confidential*

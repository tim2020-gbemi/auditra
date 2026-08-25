# Auditra

Compliance management platform for GRC engineers and analysts.
Built to reduce manual effort on control mapping, assessment tracking,
and audit reporting across six frameworks simultaneously.

Phase 1 complete. Seeking collaboration and early client partnerships.

---

## What It Does

- Maps 150 controls across six compliance frameworks simultaneously, with a curated 39-control Core baseline and full framework depth available on demand
- Tracks assessment status per control with full audit trail
- Role-based access control (Admin and Viewer roles)
- User management with self-registration and admin approval workflow
- Exports audit-ready reports in PDF, CSV, and HTML formats, filterable by Core or Full control set
- Framework filter tabs to isolate controls by standard
- Live search across all controls by ID or description
- Collapsible category sections grouped by NIST CSF function
- Priority view surfacing Non-Compliant controls, Critical/High vulnerabilities, and Critical/High risks in one place
- Live compliance score updated in real time
- Developer activity log with session tracking and statistics

---

## Frameworks Covered

| Framework | Version | Notes |
|---|---|---|
| NIST CSF | 2.0 | Core control structure |
| ISO 27001 | 2022 | International security standard |
| SOC 2 | Trust Services Criteria | Service organization controls |
| PCI-DSS | v4.0.1 | Payment card security (current active version) |
| NDPA + GAID | 2023 + 2025 | Nigeria Data Protection Act + General Application and Implementation Directive |
| GDPR | 2018 (enforced) | EU General Data Protection Regulation |

> NDPR 2019 is no longer in effect. Auditra maps to the current Nigerian
> data protection instruments: NDPA 2023 and GAID 2025, effective
> September 19, 2025.

> GDPR coverage is included for Nigerian businesses processing personal
> data of EU citizens. Auditra is the only tool mapping both NDPA/GAID
> and GDPR simultaneously.

---

## Project Structure

```
auditra/
├── compliance_mapper.py      # Control database (150 controls, 6 frameworks, Core/Full tiers)
├── app.py                    # Flask web server with auth and all routes
├── database.py               # SQLite with audit log, session log, user management
├── templates/
│   ├── login.html            # Login page
│   ├── register.html         # Self-registration page
│   ├── dashboard.html        # Main compliance dashboard
│   ├── users.html            # Admin user management
│   ├── change_password.html  # Password change page
│   ├── report.html           # PDF report template
│   ├── report_html.html      # HTML export template
│   └── devlog.html           # Developer activity log (admin only)
└── static/                   # Static assets
```

---

## Features

### Compliance Dashboard
- Live compliance score based on assessed controls
- Summary cards: Compliant, Partial, Non-Compliant, Not Assessed
- Framework filter tabs: All, NIST CSF, PCI-DSS, NDPA/GAID, GDPR
- Full controls table with all six framework mappings side by side

### Authentication & Roles
- Login required to access the dashboard
- Admin: can update control statuses and manage all users
- Viewer: read-only access to dashboard and exports
- Self-registration page with admin approval workflow
- All status changes logged with username and timestamp

### Reports & Exports
- PDF export: professional landscape layout for audit delivery
- CSV export: full dataset for spreadsheet workflows
- HTML export: styled dark mode report for digital sharing

### Audit Trail
- Every status change recorded: control, old status, new status, who, when
- Visible on the dashboard in real time

### User Management
- Admin creates accounts directly (active immediately)
- Self-registration page (pending admin approval)
- Role assignment: Admin or Viewer
- Password reset by admin for any user
- Account activation and deactivation
- Users can change their own password

### Developer Activity Log
- Tracks every login, logout, page view, export, and status update
- Records IP address and timestamp for every event
- Summary statistics: total logins, unique users, failed logins, exports
- Filter by action type: Logins, Failed, Exports, Updates, Page Views, User Actions
- Shows last 1000 events
- Clear all logs functionality for pre-deployment cleanup
- Accessible via direct URL only (/devlog), not linked from the dashboard
- Admin authentication required

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

Developer log: http://localhost:5000/devlog

---

## Controls Coverage

Auditra offers two levels of depth, selectable per view and per export.

**Core (39 controls)** — the original curated baseline, ideal for first-pass
assessments and client onboarding.

**Full (150 controls)** — comprehensive framework depth, including complete
NIST CSF 2.0 coverage across all six functions.

| Category | Core | Full |
|---|---|---|
| NIST CSF | 13 | 106 (all 6 functions, 22 categories) |
| PCI-DSS v4.0.1 | 4 | 10 (all 12 requirement areas represented) |
| NDPA 2023 + GAID 2025 | 7 | 13 |
| GDPR | 15 | 21 |
| **Total** | **39** | **150** |

### NIST CSF 2.0 Full Breakdown

| Function | Subcategories |
|---|---|
| Govern (GV) | 31 |
| Identify (ID) | 21 |
| Protect (PR) | 22 |
| Detect (DE) | 11 |
| Respond (RS) | 13 |
| Recover (RC) | 8 |
| **Total** | **106** |

---

## Competitive Position

| Platform | NIST | ISO 27001 | SOC 2 | PCI-DSS | NDPA/GAID | GDPR | Price/yr |
|---|---|---|---|---|---|---|---|
| Auditra | Yes | Yes | Yes | Yes | Yes | Yes | TBD |
| Vanta | Yes | Yes | Yes | Yes | No | Partial | $15k+ |
| Drata | Yes | Yes | Yes | Yes | No | Partial | $15k+ |
| Tugboat Logic | Yes | Yes | Yes | No | No | Partial | $10k+ |

> Auditra is the only tool with native NDPA 2023 and GAID 2025 support.
> No existing platform maps both Nigerian and EU data protection obligations simultaneously.

---

## Roadmap

- [x] Core compliance mapper CLI
- [x] Flask web app
- [x] SQLite persistent database
- [x] User authentication and roles
- [x] User management and self-registration
- [x] PDF, CSV, and HTML export (Core/Full tier selectable)
- [x] Multi-framework support: NIST CSF, ISO 27001, SOC 2, PCI-DSS v4.0.1, NDPA 2023 + GAID 2025, GDPR
- [x] Framework filter tabs
- [x] Compliance audit trail
- [x] Developer activity log with session tracking
- [x] Auditra branding
- [x] Deployed live on Render (public URL)
- [x] Vulnerability tracker with CVE to asset mapping and CVSS-based risk rating
- [x] Risk scoring engine with likelihood x impact heat map and auto-generation from controls/vulnerabilities
- [x] Email-based notifications via Resend (registration, activation, password reset, critical alerts)
- [x] Full NIST CSF 2.0 expansion (all 106 subcategories)
- [x] Deep expansion of NDPA/GAID, GDPR, and PCI-DSS controls
- [x] Core / Full / Priority dashboard views with live search and collapsible sections
- [ ] Domain verification for full email deliverability to all recipients
- [ ] Multi-tenant architecture (Phase 3)
- [ ] Paystack subscription billing (Phase 3)
- [ ] Third-party integrations: Jira, AWS Security Hub, Google Workspace (Phase 3)
- [ ] SIEM/EDR integrations: Splunk, QRadar, Microsoft Sentinel (Phase 3)
- [ ] Portfolio and marketing site

---

## Collaboration

Auditra is actively seeking:

- **GRC consultants or compliance professionals** with existing client relationships
  who want to use or co-develop the platform for client engagements
- **Technical collaborators** interested in Phase 2 and Phase 3 development
- **Nigerian fintech or enterprise partners** looking for a compliance tool
  built natively for NDPA 2023, GAID 2025, and cross-border GDPR obligations

If you are interested in collaborating, open an issue or reach out directly.

---

## About

Built by a GRC engineer and cybersecurity analyst based in Lagos, Nigeria.
Focus: reducing the manual overhead of compliance mapping and audit prep
for organizations operating under Nigerian and international data protection
and security frameworks.

Tools: Python 3, Flask, SQLite, xhtml2pdf, GitHub Copilot, VS Code.

---

*Auditra | Phase 1 Complete | Seeking Collaboration*

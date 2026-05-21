# Auditra

Security automation tool for GRC engineers and compliance analysts.
Built to reduce manual effort on control mapping, assessment tracking, and audit reporting.

Currently in active development. Phase 1 (web app) in progress.

---

## What It Does

- Maps controls across five compliance frameworks simultaneously
- Tracks assessment status per control with full audit trail
- Role-based access control (Admin and Viewer roles)
- Exports audit-ready reports in CSV, HTML, and PDF formats
- Framework filter to isolate controls by standard

---

## Frameworks Covered

| Framework | Version | Notes |
|---|---|---|
| NIST CSF | 2.0 | Core control structure |
| ISO 27001 | 2022 | International standard |
| SOC 2 | Trust Services Criteria | Service organization controls |
| PCI-DSS | v4.0.1 | Payment card security |
| NDPA + GAID | 2023 + 2025 | Nigeria Data Protection Act + General Application and Implementation Directive |

> NDPR 2019 is no longer in effect. This tool maps to the current Nigerian data protection instruments: NDPA 2023 and GAID 2025, effective September 19, 2025.

---

## Project Structure
grc-toolkit/
├── compliance_mapper.py   # Core control database (24 controls across 5 frameworks)
├── app.py                 # Flask web server with auth and routes
├── database.py            # SQLite database layer with audit logging
├── templates/
│   ├── login.html         # Login page
│   ├── dashboard.html     # Main compliance dashboard
│   └── report.html        # PDF report template
└── static/                # Static assets

---

## Features

### Compliance Dashboard
- Live compliance score based on assessed controls
- Summary cards: Compliant, Partial, Non-Compliant, Not Assessed
- Framework filter tabs: All, NIST CSF, PCI-DSS, NDPA/GAID
- Full controls table with all five framework mappings

### Authentication & Roles
- Login required to access the dashboard
- Admin: can update control statuses
- Viewer: read-only access
- All status changes logged with username and timestamp

### Reports
- CSV export for spreadsheet workflows
- HTML dashboard export for browser viewing
- PDF export for audit delivery

### Exports
- Exports audit-ready reports in PDF, CSV, and HTML formats

### Audit Trail
- Every status change recorded: control, old status, new status, who, when
- Visible on the dashboard and included in PDF reports

---

## Run Locally

```bash
pip install flask werkzeug xhtml2pdf
python app.py
```

Open: http://localhost:5000

Default credentials (change after first login):
- Admin: `admin` / `admin123`
- Viewer: `viewer` / `viewer123`

---

## Controls Coverage

| Category | Count |
|---|---|
| NIST CSF core controls | 13 |
| PCI-DSS specific | 4 |
| NDPA + GAID specific | 7 |
| **Total** | **24** |

---

## Roadmap

- [x] Core compliance mapper (CLI)
- [x] Flask web app
- [x] SQLite persistent database
- [x] User authentication and roles
- [x] PDF export
- [x] Multi-framework support (NDPA 2023 + GAID 2025)
- [ ] Deploy to DigitalOcean (public URL)
- [ ] Vulnerability tracker with CVE mapping
- [ ] Risk scoring engine
- [ ] Portfolio site

---

## About

Built by a GRC engineer and cybersecurity analyst.
Focus: reducing the manual overhead of compliance mapping and audit prep for organisations operating under Nigerian and international data protection regimes.

Tools: Python 3, Flask, SQLite, xhtml2pdf, GitHub Copilot, VS Code.

"""
Compliance Control Cross-Reference Mapper
==========================================
Maps controls across five frameworks:
- NIST CSF 2.0
- ISO 27001:2022
- SOC 2 TSC
- PCI-DSS v4.0.1
- NDPA 2023 + GAID 2025 (Nigeria Data Protection Act + General Application
  and Implementation Directive)

Note: NDPR 2019 is no longer in effect. NDPA 2023 and GAID 2025 are the
two governing instruments for data protection in Nigeria from Sept 19, 2025.

Author: Oluwatimilehin Oluwagbemi
Purpose: GRC Portfolio Project
"""

import csv
import datetime


CONTROLS_DB = {

    # ─── GOVERN ───────────────────────────────────────────────────────────────

    "GV.OC-01": {
        "nist_function":    "GOVERN",
        "nist_description": "Organizational mission, stakeholder expectations, and legal requirements are understood and documented.",
        "iso_27001":        ["5.1", "5.2", "6.1.1"],
        "iso_description":  "Leadership & organizational context",
        "soc2_tsc":         ["CC1.1", "CC1.2"],
        "soc2_description": "Control Environment - Integrity & Ethical Values",
        "pci_dss":          ["12.1", "12.2"],
        "pci_description":  "Information security policy & risk management",
        "ndpa":             ["NDPA S.24", "NDPA S.25", "GAID Art. 16"],
        "ndpa_description": "Lawful basis for processing & organizational accountability",
        "status":           "Not Assessed",
    },
    "GV.RM-01": {
        "nist_function":    "GOVERN",
        "nist_description": "Risk management objectives are established and agreed to by stakeholders.",
        "iso_27001":        ["6.1.2", "6.1.3"],
        "iso_description":  "Information security risk assessment & treatment",
        "soc2_tsc":         ["CC3.1", "CC3.2"],
        "soc2_description": "Risk Assessment - Specifies Objectives",
        "pci_dss":          ["12.2"],
        "pci_description":  "Targeted risk analysis",
        "ndpa":             ["NDPA S.28", "GAID Art. 27"],
        "ndpa_description": "Data Protection Impact Assessment (DPIA) for high-risk processing",
        "status":           "Not Assessed",
    },

    # ─── IDENTIFY ─────────────────────────────────────────────────────────────

    "ID.AM-01": {
        "nist_function":    "IDENTIFY",
        "nist_description": "Inventories of hardware managed by the organization are maintained.",
        "iso_27001":        ["8.1", "5.9"],
        "iso_description":  "Inventory of information and other associated assets",
        "soc2_tsc":         ["CC6.1"],
        "soc2_description": "Logical & Physical Access Controls",
        "pci_dss":          ["2.2", "12.5.1"],
        "pci_description":  "Secure configurations & scoped asset inventory",
        "ndpa":             ["N/A"],
        "ndpa_description": "Not directly applicable",
        "status":           "Not Assessed",
    },
    "ID.AM-02": {
        "nist_function":    "IDENTIFY",
        "nist_description": "Inventories of software, services, and systems managed by the organization are maintained.",
        "iso_27001":        ["8.1", "8.8"],
        "iso_description":  "Asset inventory & management of technical vulnerabilities",
        "soc2_tsc":         ["CC6.1", "CC7.1"],
        "soc2_description": "Logical Access & System Operations",
        "pci_dss":          ["2.2", "6.3.3"],
        "pci_description":  "Secure configurations & software patching",
        "ndpa":             ["N/A"],
        "ndpa_description": "Not directly applicable",
        "status":           "Not Assessed",
    },
    "ID.RA-01": {
        "nist_function":    "IDENTIFY",
        "nist_description": "Vulnerabilities in assets are identified, validated, and recorded.",
        "iso_27001":        ["8.8", "6.1.2"],
        "iso_description":  "Management of technical vulnerabilities & risk assessment",
        "soc2_tsc":         ["CC3.2", "CC7.1"],
        "soc2_description": "Risk Assessment & System Operations",
        "pci_dss":          ["11.3.1", "11.3.2"],
        "pci_description":  "Internal & external vulnerability scanning",
        "ndpa":             ["NDPA S.28"],
        "ndpa_description": "DPIA required where processing poses high risk to data subjects",
        "status":           "Not Assessed",
    },

    # ─── PROTECT ──────────────────────────────────────────────────────────────

    "PR.AA-01": {
        "nist_function":    "PROTECT",
        "nist_description": "Identities and credentials for authorized users, services, and hardware are managed.",
        "iso_27001":        ["5.15", "5.16", "5.17"],
        "iso_description":  "Access control, identity management, authentication",
        "soc2_tsc":         ["CC6.1", "CC6.2", "CC6.3"],
        "soc2_description": "Logical & Physical Access Controls",
        "pci_dss":          ["7.1", "8.1", "8.2"],
        "pci_description":  "Access control & user authentication",
        "ndpa":             ["NDPA S.37", "NDPA S.38"],
        "ndpa_description": "Technical & organizational security safeguards for personal data",
        "status":           "Not Assessed",
    },
    "PR.DS-01": {
        "nist_function":    "PROTECT",
        "nist_description": "The confidentiality, integrity, and availability of data-at-rest are protected.",
        "iso_27001":        ["8.24", "8.5"],
        "iso_description":  "Use of cryptography & secure authentication",
        "soc2_tsc":         ["CC6.1", "CC6.7"],
        "soc2_description": "Logical Access & Transmission Protections",
        "pci_dss":          ["3.4", "3.5"],
        "pci_description":  "Protection of stored account data & cryptography",
        "ndpa":             ["NDPA S.37", "NDPA S.38"],
        "ndpa_description": "Security measures for stored personal data",
        "status":           "Not Assessed",
    },
    "PR.DS-02": {
        "nist_function":    "PROTECT",
        "nist_description": "The confidentiality, integrity, and availability of data-in-transit are protected.",
        "iso_27001":        ["8.24", "8.20"],
        "iso_description":  "Cryptography & network security controls",
        "soc2_tsc":         ["CC6.7"],
        "soc2_description": "Transmission Integrity & Confidentiality",
        "pci_dss":          ["4.2.1"],
        "pci_description":  "Strong cryptography for data in transit",
        "ndpa":             ["NDPA S.37", "NDPA S.38"],
        "ndpa_description": "Security measures for personal data in transmission",
        "status":           "Not Assessed",
    },

    # ─── DETECT ───────────────────────────────────────────────────────────────

    "DE.CM-01": {
        "nist_function":    "DETECT",
        "nist_description": "Networks and network services are monitored to find potentially adverse events.",
        "iso_27001":        ["8.16", "8.15"],
        "iso_description":  "Monitoring activities & logging",
        "soc2_tsc":         ["CC7.2", "CC7.3"],
        "soc2_description": "System Operations - Anomaly Detection",
        "pci_dss":          ["10.2", "10.3", "10.7"],
        "pci_description":  "Audit logs & log management",
        "ndpa":             ["N/A"],
        "ndpa_description": "Not directly applicable",
        "status":           "Not Assessed",
    },
    "DE.AE-02": {
        "nist_function":    "DETECT",
        "nist_description": "Potentially adverse events are analyzed to better characterize them.",
        "iso_27001":        ["8.16", "5.25"],
        "iso_description":  "Monitoring & assessment of information security events",
        "soc2_tsc":         ["CC7.3", "CC7.4"],
        "soc2_description": "Evaluation & Response to Security Events",
        "pci_dss":          ["10.7.2", "10.7.3"],
        "pci_description":  "Detection & response to critical control failures",
        "ndpa":             ["N/A"],
        "ndpa_description": "Not directly applicable",
        "status":           "Not Assessed",
    },

    # ─── RESPOND ──────────────────────────────────────────────────────────────

    "RS.MA-01": {
        "nist_function":    "RESPOND",
        "nist_description": "The incident response plan is executed in coordination with relevant parties.",
        "iso_27001":        ["5.26", "5.24"],
        "iso_description":  "Response to information security incidents",
        "soc2_tsc":         ["CC7.4", "CC7.5"],
        "soc2_description": "Incident Response & Recovery",
        "pci_dss":          ["12.10.1", "12.10.2"],
        "pci_description":  "Incident response plan & testing",
        "ndpa":             ["NDPA S.39", "NDPA S.40"],
        "ndpa_description": "Personal data breach notification to NDPC within 72 hours",
        "status":           "Not Assessed",
    },
    "RS.CO-02": {
        "nist_function":    "RESPOND",
        "nist_description": "Internal and external stakeholders are notified of incidents.",
        "iso_27001":        ["5.26", "6.1.3"],
        "iso_description":  "Incident response & disclosure obligations",
        "soc2_tsc":         ["CC2.2", "CC7.4"],
        "soc2_description": "Communication & Incident Response",
        "pci_dss":          ["12.10.3"],
        "pci_description":  "Incident response - notification procedures",
        "ndpa":             ["NDPA S.39", "NDPA S.40"],
        "ndpa_description": "Notification to data subjects & NDPC after confirmed breach",
        "status":           "Not Assessed",
    },

    # ─── RECOVER ──────────────────────────────────────────────────────────────

    "RC.RP-01": {
        "nist_function":    "RECOVER",
        "nist_description": "The recovery portion of the incident response plan is executed once initiated.",
        "iso_27001":        ["5.29", "5.30"],
        "iso_description":  "Information security during disruption & ICT readiness",
        "soc2_tsc":         ["A1.2", "A1.3"],
        "soc2_description": "Availability - Recovery & Restoration",
        "pci_dss":          ["12.10.4"],
        "pci_description":  "Business continuity & recovery procedures",
        "ndpa":             ["N/A"],
        "ndpa_description": "Not directly applicable",
        "status":           "Not Assessed",
    },

    # ─── PCI-DSS SPECIFIC CONTROLS ────────────────────────────────────────────

    "PCI.3.1": {
        "nist_function":    "PROTECT",
        "nist_description": "Processes and mechanisms for protecting stored account data are defined and understood.",
        "iso_27001":        ["8.24", "8.11"],
        "iso_description":  "Cryptography & data masking",
        "soc2_tsc":         ["CC6.1"],
        "soc2_description": "Logical & Physical Access Controls",
        "pci_dss":          ["3.1", "3.2", "3.3"],
        "pci_description":  "Stored account data protection & minimization",
        "ndpa":             ["NDPA S.33", "NDPA S.36"],
        "ndpa_description": "Data minimization & storage limitation principles",
        "status":           "Not Assessed",
    },
    "PCI.6.1": {
        "nist_function":    "PROTECT",
        "nist_description": "Processes and mechanisms for developing and maintaining secure systems and software are defined.",
        "iso_27001":        ["8.25", "8.28"],
        "iso_description":  "Secure development lifecycle & secure coding",
        "soc2_tsc":         ["CC8.1"],
        "soc2_description": "Change Management",
        "pci_dss":          ["6.1", "6.2", "6.3"],
        "pci_description":  "Secure development policy & bespoke software security",
        "ndpa":             ["N/A"],
        "ndpa_description": "Not directly applicable",
        "status":           "Not Assessed",
    },
    "PCI.9.1": {
        "nist_function":    "PROTECT",
        "nist_description": "Physical access to the cardholder data environment is restricted.",
        "iso_27001":        ["7.1", "7.2", "7.3"],
        "iso_description":  "Physical & environmental security",
        "soc2_tsc":         ["CC6.4"],
        "soc2_description": "Physical Access Controls",
        "pci_dss":          ["9.1", "9.2", "9.3"],
        "pci_description":  "Physical security controls for cardholder data environment",
        "ndpa":             ["NDPA S.37"],
        "ndpa_description": "Physical security safeguards for personal data processing facilities",
        "status":           "Not Assessed",
    },
    "PCI.11.1": {
        "nist_function":    "IDENTIFY",
        "nist_description": "Processes and mechanisms for testing security of systems and networks are defined.",
        "iso_27001":        ["8.8", "5.36"],
        "iso_description":  "Vulnerability management & compliance review",
        "soc2_tsc":         ["CC4.1", "CC4.2"],
        "soc2_description": "Monitoring Controls",
        "pci_dss":          ["11.1", "11.4"],
        "pci_description":  "Security testing & penetration testing",
        "ndpa":             ["NDPA S.28"],
        "ndpa_description": "DPIA required for high-risk processing activities",
        "status":           "Not Assessed",
    },

    # ─── NDPA 2023 + GAID 2025 SPECIFIC CONTROLS ──────────────────────────────

    "NDPA.S27": {
        "nist_function":    "GOVERN",
        "nist_description": "Data subjects are informed of their rights and mechanisms exist to fulfill access, rectification, erasure, and portability requests.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P5.1", "P5.2"],
        "soc2_description": "Privacy - Data Subject Rights",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.27"],
        "ndpa_description": "Data subject rights: access, rectification, erasure, portability, objection",
        "status":           "Not Assessed",
    },
    "NDPA.S26": {
        "nist_function":    "GOVERN",
        "nist_description": "Valid consent is obtained before collecting or processing personal data, with clear opt-out mechanisms and cookie consent controls in place.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P3.1", "P3.2"],
        "soc2_description": "Privacy - Consent & Choice",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.26", "GAID Art. 16", "GAID Art. 19"],
        "ndpa_description": "Consent: freely given, specific, informed. Cookie consent opt-in required (GAID Art. 19)",
        "status":           "Not Assessed",
    },
    "NDPA.S33": {
        "nist_function":    "GOVERN",
        "nist_description": "Only personal data adequate and relevant to the specified purpose is collected and processed. Retention periods are defined and enforced.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P4.1"],
        "soc2_description": "Privacy - Data Minimization & Retention",
        "pci_dss":          ["3.2"],
        "pci_description":  "Account data minimization",
        "ndpa":             ["NDPA S.33", "NDPA S.36"],
        "ndpa_description": "Data minimization & storage limitation - collect only what is necessary",
        "status":           "Not Assessed",
    },
    "NDPA.S32": {
        "nist_function":    "GOVERN",
        "nist_description": "A Data Protection Officer (DPO) is designated, registered with NDPC, and submits semi-annual data protection reports included in the Record of Processing Activities (RoPA).",
        "iso_27001":        ["5.2", "5.3"],
        "iso_description":  "Information security roles & responsibilities",
        "soc2_tsc":         ["CC1.3"],
        "soc2_description": "Control Environment - Organizational Structure",
        "pci_dss":          ["12.1.1"],
        "pci_description":  "Security roles & responsibilities",
        "ndpa":             ["NDPA S.32", "GAID Art. 11", "GAID Art. 12", "GAID Art. 13"],
        "ndpa_description": "Mandatory DPO - NDPC registration, annual credential assessment (ACA), semi-annual RoPA report",
        "status":           "Not Assessed",
    },
    "NDPA.S42": {
        "nist_function":    "PROTECT",
        "nist_description": "Personal data transferred outside Nigeria is subject to adequate safeguards, NDPC adequacy decisions, or binding corporate rules.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and cross-border data transfer controls",
        "soc2_tsc":         ["CC6.7"],
        "soc2_description": "Transmission Integrity & Confidentiality",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.42", "NDPA S.43", "GAID Art. 8"],
        "ndpa_description": "Cross-border transfer: adequacy decision, binding corporate rules, or contractual clauses required",
        "status":           "Not Assessed",
    },

    # ─── GAID 2025 SPECIFIC CONTROLS (no NDPR equivalent) ─────────────────────

    "GAID.ART9": {
        "nist_function":    "GOVERN",
        "nist_description": "The organization is registered with the Nigeria Data Protection Commission (NDPC) as a data controller or processor of major importance where applicable.",
        "iso_27001":        ["5.1", "5.2"],
        "iso_description":  "Leadership & management responsibilities",
        "soc2_tsc":         ["CC1.2"],
        "soc2_description": "Control Environment - Board Oversight",
        "pci_dss":          ["12.1"],
        "pci_description":  "Security policy & compliance program",
        "ndpa":             ["GAID Art. 9"],
        "ndpa_description": "Mandatory NDPC registration for UHL, EHL, OHL entities. CAR filing annually by March 31",
        "status":           "Not Assessed",
    },
    "GAID.ART8": {
        "nist_function":    "GOVERN",
        "nist_description": "The organization has assessed whether it meets the NDPA extraterritorial threshold and applied NDPA obligations where it processes or targets personal data of persons in Nigeria.",
        "iso_27001":        ["5.1", "6.1.1"],
        "iso_description":  "Organizational context & compliance obligations",
        "soc2_tsc":         ["CC1.1"],
        "soc2_description": "Control Environment - Integrity & Ethical Values",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["GAID Art. 8"],
        "ndpa_description": "Extraterritorial reach: applies to any org targeting Nigerian data subjects regardless of physical presence",
        "status":           "Not Assessed",
    },

    # ─── GDPR CORE CONTROLS ───────────────────────────────────────────────────────
    # Covers the 15 most commonly audited GDPR articles.
    # Relevant for Nigerian businesses processing personal data of EU citizens.

    "GDPR.A5": {
        "nist_function":    "GOVERN",
        "nist_description": "Personal data is processed lawfully, fairly, and transparently. Collection is limited to specified purposes, adequate, relevant, accurate, and not kept longer than necessary.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P3.1", "P4.1"],
        "soc2_description": "Privacy - Data Use & Retention",
        "pci_dss":          ["3.2"],
        "pci_description":  "Data minimization & retention",
        "ndpa":             ["NDPA S.33", "NDPA S.36"],
        "ndpa_description": "Data minimization & storage limitation",
        "gdpr":             ["Art. 5"],
        "gdpr_description": "Principles of personal data processing: lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity",
        "status":           "Not Assessed",
    },
    "GDPR.A6": {
        "nist_function":    "GOVERN",
        "nist_description": "A documented lawful basis exists for every personal data processing activity before processing begins.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P3.1"],
        "soc2_description": "Privacy - Consent & Choice",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.24", "NDPA S.25"],
        "ndpa_description": "Lawful basis for processing personal data",
        "gdpr":             ["Art. 6"],
        "gdpr_description": "Lawful basis: consent, contract, legal obligation, vital interests, public task, or legitimate interests",
        "status":           "Not Assessed",
    },
    "GDPR.A7": {
        "nist_function":    "GOVERN",
        "nist_description": "Where consent is the lawful basis, it is freely given, specific, informed, unambiguous, and documented. Withdrawal mechanism is as easy as giving consent.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P3.1", "P3.2"],
        "soc2_description": "Privacy - Consent & Choice",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.26", "GAID Art. 19"],
        "ndpa_description": "Consent requirements & cookie consent controls",
        "gdpr":             ["Art. 7"],
        "gdpr_description": "Conditions for consent: demonstrable, clear language, withdrawable at any time, no detriment for withdrawal",
        "status":           "Not Assessed",
    },
    "GDPR.A12": {
        "nist_function":    "GOVERN",
        "nist_description": "Privacy information is provided in a concise, transparent, intelligible, and easily accessible form using clear and plain language.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P1.1"],
        "soc2_description": "Privacy - Notice & Communication",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.27"],
        "ndpa_description": "Transparency obligations to data subjects",
        "gdpr":             ["Art. 12"],
        "gdpr_description": "Transparent communication: clear language, free of charge, respond to requests within one month",
        "status":           "Not Assessed",
    },
    "GDPR.A13": {
        "nist_function":    "GOVERN",
        "nist_description": "Data subjects are provided with required privacy information at the point of data collection including identity of controller, purposes, lawful basis, retention periods, and their rights.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy notice and data subject information",
        "soc2_tsc":         ["P1.1", "P2.1"],
        "soc2_description": "Privacy - Notice at Collection",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.27"],
        "ndpa_description": "Information to be provided to data subjects",
        "gdpr":             ["Art. 13"],
        "gdpr_description": "Privacy notice at collection: controller identity, DPO contact, purposes, lawful basis, recipients, retention, data subject rights",
        "status":           "Not Assessed",
    },
    "GDPR.A15": {
        "nist_function":    "GOVERN",
        "nist_description": "Processes exist to respond to data subject access requests within one month. Responses are complete, accurate, and provided free of charge. (2024 EDPB enforcement priority)",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P5.1", "P5.2"],
        "soc2_description": "Privacy - Data Subject Access",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.27"],
        "ndpa_description": "Right of access to personal data",
        "gdpr":             ["Art. 15"],
        "gdpr_description": "Right of access: confirmation of processing, copy of data, supplementary information. Respond within one month. Active 2024-2025 EDPB enforcement focus.",
        "status":           "Not Assessed",
    },
    "GDPR.A17": {
        "nist_function":    "GOVERN",
        "nist_description": "Processes exist to erase personal data without undue delay where grounds for erasure apply, including withdrawal of consent or data no longer necessary for its purpose.",
        "iso_27001":        ["5.34", "8.10"],
        "iso_description":  "Privacy and deletion of information",
        "soc2_tsc":         ["P5.2"],
        "soc2_description": "Privacy - Data Subject Rights",
        "pci_dss":          ["3.2"],
        "pci_description":  "Data retention & disposal",
        "ndpa":             ["NDPA S.27"],
        "ndpa_description": "Right to erasure of personal data",
        "gdpr":             ["Art. 17"],
        "gdpr_description": "Right to erasure: no longer necessary, consent withdrawn, unlawful processing, legal obligation. Notify third parties of erasure request.",
        "status":           "Not Assessed",
    },
    "GDPR.A20": {
        "nist_function":    "GOVERN",
        "nist_description": "Data subjects can receive their personal data in a structured, commonly used, machine-readable format and transmit it to another controller where technically feasible.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Privacy and protection of personally identifiable information",
        "soc2_tsc":         ["P5.2"],
        "soc2_description": "Privacy - Data Subject Rights",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.27"],
        "ndpa_description": "Right to data portability",
        "gdpr":             ["Art. 20"],
        "gdpr_description": "Data portability: structured, machine-readable format. Direct transfer between controllers where technically feasible.",
        "status":           "Not Assessed",
    },
    "GDPR.A25": {
        "nist_function":    "PROTECT",
        "nist_description": "Privacy by design and default is implemented. Data protection measures are integrated into processing systems from the outset, and only necessary data is processed by default.",
        "iso_27001":        ["5.34", "8.25"],
        "iso_description":  "Privacy by design & secure development",
        "soc2_tsc":         ["CC8.1"],
        "soc2_description": "Change Management - Privacy by Design",
        "pci_dss":          ["6.1", "6.2"],
        "pci_description":  "Secure development lifecycle",
        "ndpa":             ["NDPA S.33", "NDPA S.37"],
        "ndpa_description": "Data minimization & security by design",
        "gdpr":             ["Art. 25"],
        "gdpr_description": "Privacy by design and by default: technical and organizational measures embedded into processing from design stage",
        "status":           "Not Assessed",
    },
    "GDPR.A30": {
        "nist_function":    "GOVERN",
        "nist_description": "Records of Processing Activities (RoPA) are maintained covering all processing activities, purposes, categories of data, recipients, transfers, and retention periods.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Records of processing activities",
        "soc2_tsc":         ["CC1.2"],
        "soc2_description": "Control Environment - Documentation",
        "pci_dss":          ["12.1"],
        "pci_description":  "Security policies & documentation",
        "ndpa":             ["GAID Art. 13"],
        "ndpa_description": "Record of Processing Activities (RoPA) semi-annual submission",
        "gdpr":             ["Art. 30"],
        "gdpr_description": "Records of processing: name and contact of controller, purposes, categories, recipients, third country transfers, retention periods, security measures",
        "status":           "Not Assessed",
    },
    "GDPR.A32": {
        "nist_function":    "PROTECT",
        "nist_description": "Appropriate technical and organizational measures are implemented to ensure security appropriate to the risk including encryption, pseudonymization, and resilience of processing systems.",
        "iso_27001":        ["8.24", "5.34"],
        "iso_description":  "Cryptography & privacy security measures",
        "soc2_tsc":         ["CC6.1", "CC6.7"],
        "soc2_description": "Logical Access & Transmission Protections",
        "pci_dss":          ["3.4", "4.2.1"],
        "pci_description":  "Encryption of stored & transmitted data",
        "ndpa":             ["NDPA S.37", "NDPA S.38"],
        "ndpa_description": "Technical & organizational security safeguards",
        "gdpr":             ["Art. 32"],
        "gdpr_description": "Security of processing: encryption, pseudonymization, confidentiality, integrity, availability, resilience, restoration capability, regular testing",
        "status":           "Not Assessed",
    },
    "GDPR.A33": {
        "nist_function":    "RESPOND",
        "nist_description": "Personal data breaches are notified to the supervisory authority within 72 hours of becoming aware. Notification includes nature of breach, categories affected, and measures taken.",
        "iso_27001":        ["5.26", "5.24"],
        "iso_description":  "Information security incident response",
        "soc2_tsc":         ["CC7.4", "CC7.5"],
        "soc2_description": "Incident Response & Recovery",
        "pci_dss":          ["12.10.1"],
        "pci_description":  "Incident response plan",
        "ndpa":             ["NDPA S.39", "NDPA S.40"],
        "ndpa_description": "Breach notification to NDPC within 72 hours",
        "gdpr":             ["Art. 33"],
        "gdpr_description": "Breach notification to supervisory authority within 72 hours: nature, categories, approximate numbers, DPO contact, consequences, measures taken",
        "status":           "Not Assessed",
    },
    "GDPR.A35": {
        "nist_function":    "GOVERN",
        "nist_description": "Data Protection Impact Assessments are conducted before processing likely to result in high risk to individuals, including systematic profiling, large scale processing of special categories, or systematic monitoring.",
        "iso_27001":        ["5.34", "6.1.2"],
        "iso_description":  "Privacy impact assessment & risk treatment",
        "soc2_tsc":         ["CC3.2"],
        "soc2_description": "Risk Assessment",
        "pci_dss":          ["12.2"],
        "pci_description":  "Targeted risk analysis",
        "ndpa":             ["NDPA S.28", "GAID Art. 27"],
        "ndpa_description": "Data Protection Impact Assessment for high-risk processing",
        "gdpr":             ["Art. 35"],
        "gdpr_description": "DPIA required for: systematic profiling, large scale special category data, systematic public monitoring. Consult supervisory authority if high residual risk.",
        "status":           "Not Assessed",
    },
    "GDPR.A37": {
        "nist_function":    "GOVERN",
        "nist_description": "A Data Protection Officer is designated where required, with appropriate expertise, resources, and independence. DPO contact details are published and communicated to supervisory authority.",
        "iso_27001":        ["5.2", "5.3"],
        "iso_description":  "Information security roles & responsibilities",
        "soc2_tsc":         ["CC1.3"],
        "soc2_description": "Control Environment - Organizational Structure",
        "pci_dss":          ["12.1.1"],
        "pci_description":  "Security roles & responsibilities",
        "ndpa":             ["NDPA S.32", "GAID Art. 11", "GAID Art. 12"],
        "ndpa_description": "DPO appointment, NDPC registration & independence",
        "gdpr":             ["Art. 37"],
        "gdpr_description": "DPO mandatory for: public authorities, large scale systematic monitoring, large scale special category processing. Must have expert knowledge of data protection law.",
        "status":           "Not Assessed",
    },
    "GDPR.A46": {
        "nist_function":    "PROTECT",
        "nist_description": "Transfers of personal data to third countries are subject to appropriate safeguards including standard contractual clauses, binding corporate rules, or adequacy decisions.",
        "iso_27001":        ["5.34"],
        "iso_description":  "Cross-border data transfer controls",
        "soc2_tsc":         ["CC6.7"],
        "soc2_description": "Transmission Integrity & Confidentiality",
        "pci_dss":          ["N/A"],
        "pci_description":  "Not directly applicable",
        "ndpa":             ["NDPA S.42", "NDPA S.43", "GAID Art. 8"],
        "ndpa_description": "Cross-border transfer restrictions & adequacy decisions",
        "gdpr":             ["Art. 46"],
        "gdpr_description": "Transfer safeguards: SCCs, binding corporate rules, adequacy decision, approved codes of conduct. Transfer Impact Assessments required for high-risk destinations.",
        "status":           "Not Assessed",
    },
# ═══════════════════════════════════════════════════════════════════════
    # NIST CSF 2.0 - GOVERN FUNCTION - FULL EXPANSION (tier: full)
    # 29 additional subcategories (GV.OC-01 and GV.RM-01 already exist as core)
    # ═══════════════════════════════════════════════════════════════════════

    # ─── GV.OC: Organizational Context (4 remaining) ──────────────────────────
    "GV.OC-02": {
        "nist_function": "GOVERN",
        "nist_description": "Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered.",
        "iso_27001": ["4.2"], "iso_description": "Understanding the needs and expectations of interested parties",
        "soc2_tsc": ["CC1.1"], "soc2_description": "Control Environment - Stakeholder Considerations",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["NDPA S.24"], "ndpa_description": "Understanding data subject expectations",
        "gdpr": ["Art. 5"], "gdpr_description": "Accountability principle - stakeholder consideration",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.OC-03": {
        "nist_function": "GOVERN",
        "nist_description": "Legal, regulatory, and contractual requirements regarding cybersecurity are understood and managed.",
        "iso_27001": ["4.2", "5.31"], "iso_description": "Legal, statutory, regulatory, and contractual requirements",
        "soc2_tsc": ["CC1.1"], "soc2_description": "Control Environment - Legal Compliance",
        "pci_dss": ["12.1"], "pci_description": "Information security policy addressing legal requirements",
        "ndpa": ["NDPA S.24", "GAID Art. 8"], "ndpa_description": "Understanding NDPA/GAID legal obligations",
        "gdpr": ["Art. 5", "Art. 6"], "gdpr_description": "Lawfulness and legal basis requirements",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.OC-04": {
        "nist_function": "GOVERN",
        "nist_description": "Critical objectives, capabilities, and services that stakeholders depend on or expect from the organization are understood and communicated.",
        "iso_27001": ["4.1"], "iso_description": "Understanding the organization and its context",
        "soc2_tsc": ["CC1.1"], "soc2_description": "Control Environment - Critical Objectives",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.OC-05": {
        "nist_function": "GOVERN",
        "nist_description": "Outcomes, capabilities, and services that the organization depends on are understood and communicated.",
        "iso_27001": ["4.1", "8.1"], "iso_description": "Organizational context and operational planning",
        "soc2_tsc": ["CC1.1"], "soc2_description": "Control Environment - Dependency Mapping",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── GV.RM: Risk Management Strategy (6 remaining) ────────────────────────
    "GV.RM-02": {
        "nist_function": "GOVERN",
        "nist_description": "Risk appetite and risk tolerance statements are established, communicated, and maintained.",
        "iso_27001": ["6.1.2"], "iso_description": "Information security risk assessment",
        "soc2_tsc": ["CC3.1"], "soc2_description": "Risk Assessment - Risk Tolerance",
        "pci_dss": ["12.2"], "pci_description": "Risk analysis process",
        "ndpa": ["NDPA S.28"], "ndpa_description": "Risk-based approach to data protection",
        "gdpr": ["Art. 35"], "gdpr_description": "Risk-based DPIA threshold setting",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RM-03": {
        "nist_function": "GOVERN",
        "nist_description": "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes.",
        "iso_27001": ["6.1.2", "6.1.3"], "iso_description": "Risk assessment and treatment integrated into ERM",
        "soc2_tsc": ["CC3.1", "CC3.2"], "soc2_description": "Risk Assessment - Enterprise Integration",
        "pci_dss": ["12.2"], "pci_description": "Targeted risk analysis",
        "ndpa": ["NDPA S.28"], "ndpa_description": "DPIA integrated into enterprise risk processes",
        "gdpr": ["Art. 35"], "gdpr_description": "DPIA integrated into enterprise risk management",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RM-04": {
        "nist_function": "GOVERN",
        "nist_description": "Strategic direction that describes appropriate risk response options is established and communicated.",
        "iso_27001": ["6.1.3"], "iso_description": "Information security risk treatment",
        "soc2_tsc": ["CC3.2"], "soc2_description": "Risk Assessment - Response Options",
        "pci_dss": ["12.2"], "pci_description": "Risk response planning",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RM-05": {
        "nist_function": "GOVERN",
        "nist_description": "Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties.",
        "iso_27001": ["5.5", "5.21"], "iso_description": "Contact with authorities and third-party risk communication",
        "soc2_tsc": ["CC2.2"], "soc2_description": "Communication and Information",
        "pci_dss": ["12.8"], "pci_description": "Third-party service provider management",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Third-party and cross-border communication lines",
        "gdpr": ["Art. 28"], "gdpr_description": "Processor communication and oversight",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RM-06": {
        "nist_function": "GOVERN",
        "nist_description": "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated.",
        "iso_27001": ["6.1.2"], "iso_description": "Information security risk assessment methodology",
        "soc2_tsc": ["CC3.1"], "soc2_description": "Risk Assessment - Standardized Methodology",
        "pci_dss": ["12.2"], "pci_description": "Risk analysis methodology",
        "ndpa": ["GAID Art. 27"], "ndpa_description": "Standardized DPIA methodology",
        "gdpr": ["Art. 35"], "gdpr_description": "Standardized risk scoring for DPIA",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RM-07": {
        "nist_function": "GOVERN",
        "nist_description": "Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions.",
        "iso_27001": ["6.1.1"], "iso_description": "Actions to address risks and opportunities",
        "soc2_tsc": ["CC3.1"], "soc2_description": "Risk Assessment - Opportunity Characterization",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── GV.RR: Roles, Responsibilities, and Authorities (4) ──────────────────
    "GV.RR-01": {
        "nist_function": "GOVERN",
        "nist_description": "Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving.",
        "iso_27001": ["5.1", "5.4"], "iso_description": "Leadership commitment and management responsibilities",
        "soc2_tsc": ["CC1.1", "CC1.2"], "soc2_description": "Control Environment - Leadership Accountability",
        "pci_dss": ["12.1.1"], "pci_description": "Security roles and responsibilities defined",
        "ndpa": ["NDPA S.32"], "ndpa_description": "Leadership accountability for data protection",
        "gdpr": ["Art. 24"], "gdpr_description": "Controller responsibility and accountability",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RR-02": {
        "nist_function": "GOVERN",
        "nist_description": "Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced.",
        "iso_27001": ["5.2", "5.3"], "iso_description": "Information security roles and responsibilities",
        "soc2_tsc": ["CC1.3"], "soc2_description": "Control Environment - Organizational Structure",
        "pci_dss": ["12.1.1", "12.1.3"], "pci_description": "Security roles and responsibilities documented",
        "ndpa": ["NDPA S.32", "GAID Art. 11"], "ndpa_description": "DPO roles and responsibilities",
        "gdpr": ["Art. 37", "Art. 39"], "gdpr_description": "DPO tasks and responsibilities",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RR-03": {
        "nist_function": "GOVERN",
        "nist_description": "Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies.",
        "iso_27001": ["5.1", "7.1"], "iso_description": "Leadership commitment and resources",
        "soc2_tsc": ["CC1.4"], "soc2_description": "Control Environment - Resource Allocation",
        "pci_dss": ["12.1"], "pci_description": "Adequate security resourcing",
        "ndpa": ["GAID Art. 11"], "ndpa_description": "Resourcing for DPO function",
        "gdpr": ["Art. 38"], "gdpr_description": "DPO resourcing requirements",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.RR-04": {
        "nist_function": "GOVERN",
        "nist_description": "Cybersecurity is included in human resources practices (e.g., deprovisioning, personnel screening).",
        "iso_27001": ["6.1", "6.5", "5.9"], "iso_description": "HR security including screening and termination",
        "soc2_tsc": ["CC1.4"], "soc2_description": "Control Environment - HR Security Practices",
        "pci_dss": ["7.2.4"], "pci_description": "Access review including HR deprovisioning",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Personnel security safeguards",
        "gdpr": ["Art. 32"], "gdpr_description": "Personnel security measures",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── GV.PO: Policy (2) ─────────────────────────────────────────────────────
    "GV.PO-01": {
        "nist_function": "GOVERN",
        "nist_description": "Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced.",
        "iso_27001": ["5.1"], "iso_description": "Policies for information security",
        "soc2_tsc": ["CC1.2"], "soc2_description": "Control Environment - Policy Establishment",
        "pci_dss": ["12.1"], "pci_description": "Information security policy",
        "ndpa": ["NDPA S.24"], "ndpa_description": "Data protection policy establishment",
        "gdpr": ["Art. 24"], "gdpr_description": "Appropriate policies for data protection",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.PO-02": {
        "nist_function": "GOVERN",
        "nist_description": "Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission.",
        "iso_27001": ["5.1"], "iso_description": "Review of policies for information security",
        "soc2_tsc": ["CC1.2"], "soc2_description": "Control Environment - Policy Review Cycle",
        "pci_dss": ["12.1.1"], "pci_description": "Annual policy review",
        "ndpa": ["NDPA S.24"], "ndpa_description": "Ongoing policy review for regulatory changes",
        "gdpr": ["Art. 24"], "gdpr_description": "Periodic review of data protection policies",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── GV.OV: Oversight (3) ──────────────────────────────────────────────────
    "GV.OV-01": {
        "nist_function": "GOVERN",
        "nist_description": "Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction.",
        "iso_27001": ["9.3"], "iso_description": "Management review",
        "soc2_tsc": ["CC1.2"], "soc2_description": "Control Environment - Strategy Review",
        "pci_dss": ["12.1.1"], "pci_description": "Annual review of security program",
        "ndpa": ["GAID Art. 13"], "ndpa_description": "Semi-annual RoPA and compliance review",
        "gdpr": ["Art. 24"], "gdpr_description": "Review of technical and organizational measures",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.OV-02": {
        "nist_function": "GOVERN",
        "nist_description": "The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks.",
        "iso_27001": ["9.3", "6.1.2"], "iso_description": "Management review and risk assessment update",
        "soc2_tsc": ["CC3.1"], "soc2_description": "Risk Assessment - Strategy Adjustment",
        "pci_dss": ["12.2"], "pci_description": "Risk analysis updated periodically",
        "ndpa": ["NDPA S.28"], "ndpa_description": "DPIA review and adjustment",
        "gdpr": ["Art. 35"], "gdpr_description": "DPIA review when processing changes",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.OV-03": {
        "nist_function": "GOVERN",
        "nist_description": "Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed.",
        "iso_27001": ["9.1", "9.3"], "iso_description": "Monitoring, measurement, and management review",
        "soc2_tsc": ["CC4.1", "CC4.2"], "soc2_description": "Monitoring Activities - Performance Evaluation",
        "pci_dss": ["12.1.1"], "pci_description": "Security program performance review",
        "ndpa": ["GAID Art. 13"], "ndpa_description": "Compliance performance evaluation via RoPA",
        "gdpr": ["Art. 24"], "gdpr_description": "Effectiveness review of data protection measures",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── GV.SC: Cybersecurity Supply Chain Risk Management (10) ───────────────
    "GV.SC-01": {
        "nist_function": "GOVERN",
        "nist_description": "A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders.",
        "iso_27001": ["5.19"], "iso_description": "Information security in supplier relationships",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Vendor Management",
        "pci_dss": ["12.8.1"], "pci_description": "Service provider management policy",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Third-party processor risk management",
        "gdpr": ["Art. 28"], "gdpr_description": "Processor contractual requirements",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-02": {
        "nist_function": "GOVERN",
        "nist_description": "Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally.",
        "iso_27001": ["5.19", "5.20"], "iso_description": "Supplier relationship roles and agreements",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Third-Party Roles",
        "pci_dss": ["12.8.2"], "pci_description": "Written agreements with service providers",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Processor roles and responsibilities",
        "gdpr": ["Art. 28"], "gdpr_description": "Processor obligations under data processing agreements",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-03": {
        "nist_function": "GOVERN",
        "nist_description": "Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes.",
        "iso_27001": ["5.19", "6.1.2"], "iso_description": "Supplier risk integrated into ISMS",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Supply Chain Integration",
        "pci_dss": ["12.8"], "pci_description": "Service provider risk management program",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Third-party risk integrated into DPIA",
        "gdpr": ["Art. 28", "Art. 35"], "gdpr_description": "Processor risk integrated into DPIA",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-04": {
        "nist_function": "GOVERN",
        "nist_description": "Suppliers are known and prioritized by criticality.",
        "iso_27001": ["5.19"], "iso_description": "Supplier inventory and criticality assessment",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Vendor Criticality",
        "pci_dss": ["12.8.1"], "pci_description": "List of service providers maintained",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 30"], "gdpr_description": "Records of processing including processor list",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-05": {
        "nist_function": "GOVERN",
        "nist_description": "Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other relevant third parties.",
        "iso_27001": ["5.20"], "iso_description": "Addressing information security within supplier agreements",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Contractual Requirements",
        "pci_dss": ["12.8.2"], "pci_description": "Security requirements in service provider agreements",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Data protection clauses in processor contracts",
        "gdpr": ["Art. 28"], "gdpr_description": "Mandatory contractual clauses for processors",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-06": {
        "nist_function": "GOVERN",
        "nist_description": "Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships.",
        "iso_27001": ["5.19"], "iso_description": "Pre-engagement supplier due diligence",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Vendor Due Diligence",
        "pci_dss": ["12.8.3"], "pci_description": "Due diligence prior to engagement",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Due diligence for cross-border transfer partners",
        "gdpr": ["Art. 28"], "gdpr_description": "Processor due diligence before engagement",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-07": {
        "nist_function": "GOVERN",
        "nist_description": "The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored over the course of the relationship.",
        "iso_27001": ["5.19", "5.22"], "iso_description": "Monitoring and review of supplier services",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Ongoing Vendor Monitoring",
        "pci_dss": ["12.8.4"], "pci_description": "Service provider compliance monitoring program",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Ongoing monitoring of processor compliance",
        "gdpr": ["Art. 28"], "gdpr_description": "Ongoing processor compliance monitoring",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-08": {
        "nist_function": "GOVERN",
        "nist_description": "Relevant suppliers and other third parties are included in incident planning, response, and recovery activities.",
        "iso_27001": ["5.26"], "iso_description": "Third parties included in incident response",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Third-Party Coordination",
        "pci_dss": ["12.10.1"], "pci_description": "Third parties in incident response plan",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Processor breach notification obligations",
        "gdpr": ["Art. 28", "Art. 33"], "gdpr_description": "Processor obligation to notify controller of breach",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-09": {
        "nist_function": "GOVERN",
        "nist_description": "Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and service life cycle.",
        "iso_27001": ["5.19", "5.23"], "iso_description": "Supply chain security in cloud and lifecycle management",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Lifecycle Monitoring",
        "pci_dss": ["12.8"], "pci_description": "Ongoing service provider program monitoring",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 28"], "gdpr_description": "Processor lifecycle compliance monitoring",
        "status": "Not Assessed", "tier": "full",
    },
    "GV.SC-10": {
        "nist_function": "GOVERN",
        "nist_description": "Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement.",
        "iso_27001": ["5.20"], "iso_description": "Termination provisions in supplier agreements",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Offboarding Provisions",
        "pci_dss": ["12.8.5"], "pci_description": "Service provider offboarding requirements",
        "ndpa": ["NDPA S.33"], "ndpa_description": "Data return or deletion after contract termination",
        "gdpr": ["Art. 28"], "gdpr_description": "Data deletion or return upon contract termination",
        "status": "Not Assessed", "tier": "full",
    },
# ═══════════════════════════════════════════════════════════════════════
    # NIST CSF 2.0 - IDENTIFY FUNCTION - FULL EXPANSION (tier: full)
    # 18 additional subcategories (ID.AM-01, ID.AM-02, ID.RA-01 already core)
    # ═══════════════════════════════════════════════════════════════════════

    # ─── ID.AM: Asset Management (5 remaining - note: AM-06 does not exist, moved to GV.RR) ──
    "ID.AM-03": {
        "nist_function": "IDENTIFY",
        "nist_description": "Representations of the organization's authorized network communication and internal and external network data flows are maintained.",
        "iso_27001": ["8.1", "5.9"], "iso_description": "Network diagrams and data flow mapping",
        "soc2_tsc": ["CC6.1"], "soc2_description": "Logical Access - Network Documentation",
        "pci_dss": ["1.2.2"], "pci_description": "Network diagrams and data flow diagrams",
        "ndpa": ["NDPA S.30"], "ndpa_description": "Records of processing activities including data flows",
        "gdpr": ["Art. 30"], "gdpr_description": "Records of processing including data flow documentation",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.AM-04": {
        "nist_function": "IDENTIFY",
        "nist_description": "Inventories of services provided by suppliers are maintained.",
        "iso_27001": ["5.19"], "iso_description": "Supplier service inventory",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Supplier Service Inventory",
        "pci_dss": ["12.8.1"], "pci_description": "List of service providers maintained",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 30"], "gdpr_description": "Records of processing including processor services",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.AM-05": {
        "nist_function": "IDENTIFY",
        "nist_description": "Assets are prioritized based on classification, criticality, resources, and impact on the mission.",
        "iso_27001": ["5.9", "5.12"], "iso_description": "Asset inventory and classification",
        "soc2_tsc": ["CC6.1"], "soc2_description": "Logical Access - Asset Prioritization",
        "pci_dss": ["12.5.1"], "pci_description": "Asset inventory with criticality classification",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 30", "Art. 32"], "gdpr_description": "Prioritization of personal data assets by risk",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.AM-07": {
        "nist_function": "IDENTIFY",
        "nist_description": "Data are managed consistent with the organization's risk strategy.",
        "iso_27001": ["5.12", "8.10"], "iso_description": "Data classification and handling",
        "soc2_tsc": ["P4.1"], "soc2_description": "Privacy - Data Management",
        "pci_dss": ["3.2"], "pci_description": "Data retention and management policy",
        "ndpa": ["NDPA S.33", "NDPA S.36"], "ndpa_description": "Data minimization and retention management",
        "gdpr": ["Art. 5", "Art. 25"], "gdpr_description": "Data management consistent with privacy principles",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.AM-08": {
        "nist_function": "IDENTIFY",
        "nist_description": "Systems, hardware, software, services, and data are managed throughout their life cycles.",
        "iso_27001": ["8.1", "5.9"], "iso_description": "Asset lifecycle management",
        "soc2_tsc": ["CC6.1"], "soc2_description": "Logical Access - Asset Lifecycle",
        "pci_dss": ["12.5.1"], "pci_description": "Asset lifecycle tracking",
        "ndpa": ["NDPA S.36"], "ndpa_description": "Data lifecycle and storage limitation",
        "gdpr": ["Art. 5"], "gdpr_description": "Storage limitation across data lifecycle",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── ID.RA: Risk Assessment (9 remaining) ─────────────────────────────────
    "ID.RA-02": {
        "nist_function": "IDENTIFY",
        "nist_description": "Cyber threat intelligence is received from information sharing forums and sources.",
        "iso_27001": ["5.7"], "iso_description": "Threat intelligence",
        "soc2_tsc": ["CC3.2"], "soc2_description": "Risk Assessment - Threat Intelligence",
        "pci_dss": ["12.2"], "pci_description": "Threat intelligence integrated into risk analysis",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-03": {
        "nist_function": "IDENTIFY",
        "nist_description": "Internal and external threats to the organization are identified and recorded.",
        "iso_27001": ["5.7", "8.8"], "iso_description": "Threat and vulnerability identification",
        "soc2_tsc": ["CC3.2"], "soc2_description": "Risk Assessment - Threat Identification",
        "pci_dss": ["12.2"], "pci_description": "Threat identification in risk analysis",
        "ndpa": ["NDPA S.28"], "ndpa_description": "Threat identification for DPIA",
        "gdpr": ["Art. 35"], "gdpr_description": "Threat identification for DPIA",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-04": {
        "nist_function": "IDENTIFY",
        "nist_description": "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded.",
        "iso_27001": ["6.1.2"], "iso_description": "Risk assessment - impact and likelihood analysis",
        "soc2_tsc": ["CC3.2"], "soc2_description": "Risk Assessment - Impact and Likelihood",
        "pci_dss": ["12.2"], "pci_description": "Impact and likelihood assessment",
        "ndpa": ["NDPA S.28"], "ndpa_description": "Likelihood and impact assessment in DPIA",
        "gdpr": ["Art. 35"], "gdpr_description": "Risk of varying likelihood and severity assessment",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-05": {
        "nist_function": "IDENTIFY",
        "nist_description": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization.",
        "iso_27001": ["6.1.2", "6.1.3"], "iso_description": "Risk assessment and treatment prioritization",
        "soc2_tsc": ["CC3.2"], "soc2_description": "Risk Assessment - Risk Prioritization",
        "pci_dss": ["12.2"], "pci_description": "Risk-based prioritization of remediation",
        "ndpa": ["NDPA S.28"], "ndpa_description": "Risk prioritization from DPIA outcomes",
        "gdpr": ["Art. 35"], "gdpr_description": "Risk-based prioritization from DPIA",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-06": {
        "nist_function": "IDENTIFY",
        "nist_description": "Risk responses are chosen, prioritized, planned, tracked, and communicated.",
        "iso_27001": ["6.1.3"], "iso_description": "Information security risk treatment",
        "soc2_tsc": ["CC3.2"], "soc2_description": "Risk Assessment - Response Tracking",
        "pci_dss": ["12.2"], "pci_description": "Risk response tracking",
        "ndpa": ["NDPA S.28"], "ndpa_description": "Risk mitigation measures from DPIA",
        "gdpr": ["Art. 35"], "gdpr_description": "Measures to address risks identified in DPIA",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-07": {
        "nist_function": "IDENTIFY",
        "nist_description": "Changes and exceptions are managed, assessed for risk impact, recorded, and tracked.",
        "iso_27001": ["8.32"], "iso_description": "Change management",
        "soc2_tsc": ["CC8.1"], "soc2_description": "Change Management",
        "pci_dss": ["6.5.1"], "pci_description": "Change control processes",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-08": {
        "nist_function": "IDENTIFY",
        "nist_description": "Processes for receiving, analyzing, and responding to vulnerability disclosures are established.",
        "iso_27001": ["5.7", "8.8"], "iso_description": "Vulnerability disclosure process",
        "soc2_tsc": ["CC7.1"], "soc2_description": "System Operations - Vulnerability Disclosure",
        "pci_dss": ["6.3.1"], "pci_description": "Vulnerability identification and response process",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-09": {
        "nist_function": "IDENTIFY",
        "nist_description": "The authenticity and integrity of hardware and software are assessed prior to acquisition and use.",
        "iso_27001": ["5.20", "8.30"], "iso_description": "Supplier agreements and outsourced development integrity",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Supply Chain Integrity",
        "pci_dss": ["6.3.2"], "pci_description": "Software integrity verification before use",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.RA-10": {
        "nist_function": "IDENTIFY",
        "nist_description": "Critical suppliers are assessed prior to acquisition.",
        "iso_27001": ["5.19", "5.20"], "iso_description": "Supplier relationship due diligence",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Critical Supplier Assessment",
        "pci_dss": ["12.8.3"], "pci_description": "Due diligence for critical service providers",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Assessment of critical processors before engagement",
        "gdpr": ["Art. 28"], "gdpr_description": "Assessment of processor before engagement",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── ID.IM: Improvement (4) ────────────────────────────────────────────────
    "ID.IM-01": {
        "nist_function": "IDENTIFY",
        "nist_description": "Improvements are identified from evaluations.",
        "iso_27001": ["9.3", "10.1"], "iso_description": "Management review and continual improvement",
        "soc2_tsc": ["CC4.1"], "soc2_description": "Monitoring Activities - Evaluation-Based Improvement",
        "pci_dss": ["12.1.1"], "pci_description": "Security program review-driven improvement",
        "ndpa": ["GAID Art. 13"], "ndpa_description": "Improvements from semi-annual compliance review",
        "gdpr": ["Art. 24"], "gdpr_description": "Improvement of measures following review",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.IM-02": {
        "nist_function": "IDENTIFY",
        "nist_description": "Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties.",
        "iso_27001": ["8.8", "5.36"], "iso_description": "Vulnerability testing and compliance review",
        "soc2_tsc": ["CC4.2"], "soc2_description": "Monitoring Activities - Testing-Driven Improvement",
        "pci_dss": ["11.4"], "pci_description": "Penetration testing driven remediation",
        "ndpa": ["NDPA S.28"], "ndpa_description": "Improvements from DPIA testing outcomes",
        "gdpr": ["Art. 32"], "gdpr_description": "Regular testing and evaluation of measures",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.IM-03": {
        "nist_function": "IDENTIFY",
        "nist_description": "Improvements are identified from execution of operational processes, procedures, and activities.",
        "iso_27001": ["10.1"], "iso_description": "Continual improvement",
        "soc2_tsc": ["CC4.1"], "soc2_description": "Monitoring Activities - Operational Improvement",
        "pci_dss": ["12.1.1"], "pci_description": "Operational review-driven improvement",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "ID.IM-04": {
        "nist_function": "IDENTIFY",
        "nist_description": "Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved.",
        "iso_27001": ["5.24", "5.29"], "iso_description": "Incident management planning and continuity",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Plan Maintenance",
        "pci_dss": ["12.10.1"], "pci_description": "Incident response plan maintained and tested",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Breach response plan maintenance",
        "gdpr": ["Art. 33"], "gdpr_description": "Maintained breach notification procedures",
        "status": "Not Assessed", "tier": "full",
    },
# ═══════════════════════════════════════════════════════════════════════
    # NIST CSF 2.0 - PROTECT FUNCTION - FULL EXPANSION (tier: full)
    # 19 additional subcategories (PR.AA-01, PR.DS-01, PR.DS-02 already core)
    # ═══════════════════════════════════════════════════════════════════════

    # ─── PR.AA: Identity Management, Authentication, and Access Control (5 remaining) ──
    "PR.AA-02": {
        "nist_function": "PROTECT",
        "nist_description": "Identities are proofed and bound to credentials based on the context of interactions.",
        "iso_27001": ["5.16", "5.17"], "iso_description": "Identity management and authentication information",
        "soc2_tsc": ["CC6.1", "CC6.2"], "soc2_description": "Logical Access - Identity Proofing",
        "pci_dss": ["8.2"], "pci_description": "User identification and authentication",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Identity verification safeguards",
        "gdpr": ["Art. 32"], "gdpr_description": "Authentication as a security measure",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.AA-03": {
        "nist_function": "PROTECT",
        "nist_description": "Users, services, and hardware are authenticated.",
        "iso_27001": ["5.17", "8.5"], "iso_description": "Authentication information and secure authentication",
        "soc2_tsc": ["CC6.1"], "soc2_description": "Logical Access - Authentication",
        "pci_dss": ["8.3"], "pci_description": "Strong authentication for users and administrators",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Authentication safeguards for personal data access",
        "gdpr": ["Art. 32"], "gdpr_description": "Authentication measures for confidentiality",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.AA-04": {
        "nist_function": "PROTECT",
        "nist_description": "Identity assertions are protected, conveyed, and verified.",
        "iso_27001": ["8.5"], "iso_description": "Secure authentication protocols",
        "soc2_tsc": ["CC6.1"], "soc2_description": "Logical Access - Identity Assertion Protection",
        "pci_dss": ["8.3.2"], "pci_description": "Secure transmission of authentication credentials",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Protection of identity assertions in transit",
        "gdpr": ["Art. 32"], "gdpr_description": "Security of authentication data in transmission",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.AA-05": {
        "nist_function": "PROTECT",
        "nist_description": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties.",
        "iso_27001": ["5.15", "5.18"], "iso_description": "Access control policy and access rights",
        "soc2_tsc": ["CC6.1", "CC6.3"], "soc2_description": "Logical Access - Least Privilege",
        "pci_dss": ["7.2"], "pci_description": "Access control based on least privilege",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Access management safeguards",
        "gdpr": ["Art. 32"], "gdpr_description": "Access control as a technical measure",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.AA-06": {
        "nist_function": "PROTECT",
        "nist_description": "Physical access to assets is managed, monitored, and enforced commensurate with risk.",
        "iso_27001": ["7.1", "7.2", "7.3"], "iso_description": "Physical security perimeters and entry controls",
        "soc2_tsc": ["CC6.4"], "soc2_description": "Physical Access Controls",
        "pci_dss": ["9.1", "9.2"], "pci_description": "Physical access controls for cardholder data environment",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Physical security safeguards",
        "gdpr": ["Art. 32"], "gdpr_description": "Physical security as an organizational measure",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── PR.AT: Awareness and Training (2) ─────────────────────────────────────
    "PR.AT-01": {
        "nist_function": "PROTECT",
        "nist_description": "Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind.",
        "iso_27001": ["6.3"], "iso_description": "Information security awareness, education and training",
        "soc2_tsc": ["CC1.4"], "soc2_description": "Control Environment - Security Awareness Training",
        "pci_dss": ["12.6.1"], "pci_description": "Security awareness program for all personnel",
        "ndpa": ["GAID Art. 12"], "ndpa_description": "Staff training on data protection obligations",
        "gdpr": ["Art. 39"], "gdpr_description": "Staff awareness and training coordinated by DPO",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.AT-02": {
        "nist_function": "PROTECT",
        "nist_description": "Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind.",
        "iso_27001": ["6.3"], "iso_description": "Role-specific security training",
        "soc2_tsc": ["CC1.4"], "soc2_description": "Control Environment - Specialized Role Training",
        "pci_dss": ["12.6.2"], "pci_description": "Role-based security awareness training",
        "ndpa": ["GAID Art. 11"], "ndpa_description": "Specialized DPO training and credentialing",
        "gdpr": ["Art. 37", "Art. 38"], "gdpr_description": "DPO expert knowledge requirements",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── PR.DS: Data Security (2 remaining) ────────────────────────────────────
    "PR.DS-10": {
        "nist_function": "PROTECT",
        "nist_description": "The confidentiality, integrity, and availability of data-in-use are protected.",
        "iso_27001": ["8.24"], "iso_description": "Cryptography for data in use",
        "soc2_tsc": ["CC6.1"], "soc2_description": "Logical Access - Data in Use Protection",
        "pci_dss": ["3.5"], "pci_description": "Protection of account data during processing",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Security measures for data during processing",
        "gdpr": ["Art. 32"], "gdpr_description": "Security of processing including data in use",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.DS-11": {
        "nist_function": "PROTECT",
        "nist_description": "Backups of data are created, protected, maintained, and tested.",
        "iso_27001": ["8.13"], "iso_description": "Information backup",
        "soc2_tsc": ["A1.2"], "soc2_description": "Availability - Backup and Recovery",
        "pci_dss": ["12.10.1"], "pci_description": "Data backup as part of incident recovery",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Backup safeguards for data availability",
        "gdpr": ["Art. 32"], "gdpr_description": "Ability to restore availability after incident",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── PR.PS: Platform Security (6) ──────────────────────────────────────────
    "PR.PS-01": {
        "nist_function": "PROTECT",
        "nist_description": "Configuration management practices are established and applied.",
        "iso_27001": ["8.9"], "iso_description": "Configuration management",
        "soc2_tsc": ["CC6.1"], "soc2_description": "Logical Access - Configuration Management",
        "pci_dss": ["2.2"], "pci_description": "Secure configuration standards",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Configuration as a technical measure",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.PS-02": {
        "nist_function": "PROTECT",
        "nist_description": "Software is maintained, replaced, and removed commensurate with risk.",
        "iso_27001": ["8.8", "8.19"], "iso_description": "Vulnerability management and software installation",
        "soc2_tsc": ["CC7.1"], "soc2_description": "System Operations - Software Maintenance",
        "pci_dss": ["6.3.3"], "pci_description": "Patch management for software",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.PS-03": {
        "nist_function": "PROTECT",
        "nist_description": "Hardware is maintained, replaced, and removed commensurate with risk.",
        "iso_27001": ["7.10", "7.13"], "iso_description": "Storage media and equipment maintenance",
        "soc2_tsc": ["CC6.4"], "soc2_description": "Physical Access - Hardware Maintenance",
        "pci_dss": ["9.4"], "pci_description": "Media and hardware disposal and maintenance",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Secure hardware disposal safeguards",
        "gdpr": ["Art. 32"], "gdpr_description": "Hardware security as organizational measure",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.PS-04": {
        "nist_function": "PROTECT",
        "nist_description": "Log records are generated and made available for continuous monitoring.",
        "iso_27001": ["8.15"], "iso_description": "Logging",
        "soc2_tsc": ["CC7.2"], "soc2_description": "System Operations - Log Generation",
        "pci_dss": ["10.2"], "pci_description": "Audit log generation",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Logging as accountability measure",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.PS-05": {
        "nist_function": "PROTECT",
        "nist_description": "Installation and execution of unauthorized software are prevented.",
        "iso_27001": ["8.19", "8.7"], "iso_description": "Software installation controls and malware protection",
        "soc2_tsc": ["CC6.8"], "soc2_description": "Logical Access - Unauthorized Software Prevention",
        "pci_dss": ["5.2"], "pci_description": "Anti-malware and unauthorized software prevention",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.PS-06": {
        "nist_function": "PROTECT",
        "nist_description": "Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle.",
        "iso_27001": ["8.25", "8.28"], "iso_description": "Secure development lifecycle and secure coding",
        "soc2_tsc": ["CC8.1"], "soc2_description": "Change Management - Secure Development",
        "pci_dss": ["6.2"], "pci_description": "Bespoke and custom software security",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 25"], "gdpr_description": "Privacy by design in software development",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── PR.IR: Technology Infrastructure Resilience (4) ───────────────────────
    "PR.IR-01": {
        "nist_function": "PROTECT",
        "nist_description": "Networks and environments are protected from unauthorized logical access and usage.",
        "iso_27001": ["8.20", "8.22"], "iso_description": "Network security and segregation",
        "soc2_tsc": ["CC6.6"], "soc2_description": "Logical Access - Network Protection",
        "pci_dss": ["1.3"], "pci_description": "Network access controls",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Network security safeguards",
        "gdpr": ["Art. 32"], "gdpr_description": "Network security as technical measure",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.IR-02": {
        "nist_function": "PROTECT",
        "nist_description": "The organization's technology assets are protected from environmental threats.",
        "iso_27001": ["7.5", "7.8"], "iso_description": "Protection against environmental threats",
        "soc2_tsc": ["A1.2"], "soc2_description": "Availability - Environmental Protection",
        "pci_dss": ["9.1"], "pci_description": "Environmental controls for facilities",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Resilience against environmental threats",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.IR-03": {
        "nist_function": "PROTECT",
        "nist_description": "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations.",
        "iso_27001": ["5.29", "5.30"], "iso_description": "Information security during disruption and ICT readiness",
        "soc2_tsc": ["A1.1", "A1.3"], "soc2_description": "Availability - Resilience Mechanisms",
        "pci_dss": ["12.10.4"], "pci_description": "Business continuity and disaster recovery",
        "ndpa": ["NDPA S.37"], "ndpa_description": "Resilience of processing systems",
        "gdpr": ["Art. 32"], "gdpr_description": "Ability to ensure resilience of processing systems",
        "status": "Not Assessed", "tier": "full",
    },
    "PR.IR-04": {
        "nist_function": "PROTECT",
        "nist_description": "Adequate resource capacity to ensure availability is maintained.",
        "iso_27001": ["8.6"], "iso_description": "Capacity management",
        "soc2_tsc": ["A1.1"], "soc2_description": "Availability - Capacity Planning",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Availability guarantee through capacity planning",
        "status": "Not Assessed", "tier": "full",
    },
# ═══════════════════════════════════════════════════════════════════════
    # NIST CSF 2.0 - DETECT FUNCTION - FULL EXPANSION (tier: full)
    # 9 additional subcategories (DE.CM-01, DE.AE-02 already core)
    # ═══════════════════════════════════════════════════════════════════════

    # ─── DE.CM: Continuous Monitoring (4 remaining) ───────────────────────────
    "DE.CM-02": {
        "nist_function": "DETECT",
        "nist_description": "The physical environment is monitored to find potentially adverse events.",
        "iso_27001": ["7.4"], "iso_description": "Physical security monitoring",
        "soc2_tsc": ["CC6.4"], "soc2_description": "Physical Access Controls - Monitoring",
        "pci_dss": ["9.5"], "pci_description": "Physical access monitoring",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Physical monitoring as security measure",
        "status": "Not Assessed", "tier": "full",
    },
    "DE.CM-03": {
        "nist_function": "DETECT",
        "nist_description": "Personnel activity and technology usage are monitored to find potentially adverse events.",
        "iso_27001": ["8.16"], "iso_description": "Monitoring activities",
        "soc2_tsc": ["CC7.2"], "soc2_description": "System Operations - Personnel Activity Monitoring",
        "pci_dss": ["10.2.1"], "pci_description": "User activity logging and monitoring",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Monitoring as accountability measure",
        "status": "Not Assessed", "tier": "full",
    },
    "DE.CM-06": {
        "nist_function": "DETECT",
        "nist_description": "External service provider activities and services are monitored to find potentially adverse events.",
        "iso_27001": ["5.22"], "iso_description": "Monitoring, review and change management of supplier services",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Vendor Activity Monitoring",
        "pci_dss": ["12.8.4"], "pci_description": "Service provider compliance monitoring",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Monitoring of third-party processor activity",
        "gdpr": ["Art. 28"], "gdpr_description": "Ongoing processor compliance monitoring",
        "status": "Not Assessed", "tier": "full",
    },
    "DE.CM-09": {
        "nist_function": "DETECT",
        "nist_description": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events.",
        "iso_27001": ["8.16", "8.15"], "iso_description": "Monitoring activities and logging",
        "soc2_tsc": ["CC7.2"], "soc2_description": "System Operations - Infrastructure Monitoring",
        "pci_dss": ["10.2"], "pci_description": "Audit logging of system components",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Continuous monitoring of processing systems",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── DE.AE: Adverse Event Analysis (5 remaining) ──────────────────────────
    "DE.AE-03": {
        "nist_function": "DETECT",
        "nist_description": "Information is correlated from multiple sources.",
        "iso_27001": ["8.16"], "iso_description": "Correlation of monitoring information",
        "soc2_tsc": ["CC7.2"], "soc2_description": "System Operations - Event Correlation",
        "pci_dss": ["10.4"], "pci_description": "Log correlation and review",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "DE.AE-04": {
        "nist_function": "DETECT",
        "nist_description": "The estimated impact and scope of adverse events are understood.",
        "iso_27001": ["5.25"], "iso_description": "Assessment and decision on information security events",
        "soc2_tsc": ["CC7.3"], "soc2_description": "System Operations - Impact Assessment",
        "pci_dss": ["12.10.1"], "pci_description": "Incident impact assessment procedures",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Breach impact assessment for notification threshold",
        "gdpr": ["Art. 33"], "gdpr_description": "Assessment of breach risk to data subjects",
        "status": "Not Assessed", "tier": "full",
    },
    "DE.AE-06": {
        "nist_function": "DETECT",
        "nist_description": "Information on adverse events is provided to authorized staff and tools.",
        "iso_27001": ["5.25", "5.26"], "iso_description": "Event assessment and incident response communication",
        "soc2_tsc": ["CC7.3"], "soc2_description": "System Operations - Event Communication",
        "pci_dss": ["12.10.2"], "pci_description": "Incident notification to relevant personnel",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Internal breach notification procedures",
        "gdpr": ["Art. 33"], "gdpr_description": "Internal escalation of breach information",
        "status": "Not Assessed", "tier": "full",
    },
    "DE.AE-07": {
        "nist_function": "DETECT",
        "nist_description": "Cyber threat intelligence and other contextual information are integrated into the analysis.",
        "iso_27001": ["5.7"], "iso_description": "Threat intelligence integration",
        "soc2_tsc": ["CC3.2"], "soc2_description": "Risk Assessment - Threat Intelligence Integration",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "DE.AE-08": {
        "nist_function": "DETECT",
        "nist_description": "Incidents are declared when adverse events meet the defined incident criteria.",
        "iso_27001": ["5.24", "5.25"], "iso_description": "Incident management planning and event assessment",
        "soc2_tsc": ["CC7.3"], "soc2_description": "System Operations - Incident Declaration",
        "pci_dss": ["12.10.1"], "pci_description": "Incident declaration criteria",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Breach declaration criteria for 72-hour notification",
        "gdpr": ["Art. 33"], "gdpr_description": "Breach awareness triggering 72-hour notification clock",
        "status": "Not Assessed", "tier": "full",
    },
# ═══════════════════════════════════════════════════════════════════════
    # NIST CSF 2.0 - RESPOND FUNCTION - FULL EXPANSION (tier: full)
    # 11 additional subcategories (RS.MA-01, RS.CO-02 already core)
    # ═══════════════════════════════════════════════════════════════════════

    # ─── RS.MA: Incident Management (4 remaining) ─────────────────────────────
    "RS.MA-02": {
        "nist_function": "RESPOND",
        "nist_description": "Incident reports are triaged and validated.",
        "iso_27001": ["5.25"], "iso_description": "Assessment and decision on information security events",
        "soc2_tsc": ["CC7.3"], "soc2_description": "System Operations - Incident Triage",
        "pci_dss": ["12.10.1"], "pci_description": "Incident report triage procedures",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Breach report validation prior to notification",
        "gdpr": ["Art. 33"], "gdpr_description": "Assessment of reported breach validity",
        "status": "Not Assessed", "tier": "full",
    },
    "RS.MA-03": {
        "nist_function": "RESPOND",
        "nist_description": "Incidents are categorized and prioritized.",
        "iso_27001": ["5.25"], "iso_description": "Categorization of information security events",
        "soc2_tsc": ["CC7.3"], "soc2_description": "System Operations - Incident Categorization",
        "pci_dss": ["12.10.1"], "pci_description": "Incident severity classification",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Breach severity classification for notification timeline",
        "gdpr": ["Art. 33"], "gdpr_description": "Breach categorization by risk level",
        "status": "Not Assessed", "tier": "full",
    },
    "RS.MA-04": {
        "nist_function": "RESPOND",
        "nist_description": "Incidents are escalated or elevated as needed.",
        "iso_27001": ["5.26"], "iso_description": "Response to information security incidents",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Escalation",
        "pci_dss": ["12.10.1"], "pci_description": "Incident escalation procedures",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Escalation to NDPC for reportable breaches",
        "gdpr": ["Art. 33"], "gdpr_description": "Escalation to supervisory authority",
        "status": "Not Assessed", "tier": "full",
    },
    "RS.MA-05": {
        "nist_function": "RESPOND",
        "nist_description": "The criteria for initiating incident recovery are applied.",
        "iso_27001": ["5.29"], "iso_description": "Information security during disruption",
        "soc2_tsc": ["CC7.5"], "soc2_description": "Incident Response - Recovery Initiation",
        "pci_dss": ["12.10.4"], "pci_description": "Recovery initiation criteria",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── RS.AN: Incident Analysis (4) ──────────────────────────────────────────
    "RS.AN-03": {
        "nist_function": "RESPOND",
        "nist_description": "Analysis is performed to establish what has taken place during an incident and the root cause of the incident.",
        "iso_27001": ["5.27"], "iso_description": "Learning from information security incidents",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Root Cause Analysis",
        "pci_dss": ["12.10.1"], "pci_description": "Root cause analysis of incidents",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Root cause analysis for breach report",
        "gdpr": ["Art. 33"], "gdpr_description": "Nature of breach analysis for notification",
        "status": "Not Assessed", "tier": "full",
    },
    "RS.AN-06": {
        "nist_function": "RESPOND",
        "nist_description": "Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved.",
        "iso_27001": ["5.28"], "iso_description": "Collection of evidence",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Evidence Preservation",
        "pci_dss": ["12.10.1"], "pci_description": "Forensic evidence preservation procedures",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 5"], "gdpr_description": "Accountability - investigation records",
        "status": "Not Assessed", "tier": "full",
    },
    "RS.AN-07": {
        "nist_function": "RESPOND",
        "nist_description": "Incident data and metadata are collected, and their integrity and provenance are preserved.",
        "iso_27001": ["5.28"], "iso_description": "Collection of evidence and data preservation",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Data Preservation",
        "pci_dss": ["10.5"], "pci_description": "Audit log integrity preservation",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 5"], "gdpr_description": "Integrity of breach investigation data",
        "status": "Not Assessed", "tier": "full",
    },
    "RS.AN-08": {
        "nist_function": "RESPOND",
        "nist_description": "An incident's magnitude is estimated and validated.",
        "iso_27001": ["5.25"], "iso_description": "Assessment and decision on information security events",
        "soc2_tsc": ["CC7.3"], "soc2_description": "System Operations - Magnitude Estimation",
        "pci_dss": ["12.10.1"], "pci_description": "Incident magnitude assessment",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Breach magnitude estimation for notification content",
        "gdpr": ["Art. 33"], "gdpr_description": "Approximate number of data subjects and records affected",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── RS.CO: Incident Response Reporting and Communication (1 remaining) ──
    "RS.CO-03": {
        "nist_function": "RESPOND",
        "nist_description": "Information is shared with designated internal and external stakeholders.",
        "iso_27001": ["5.5", "5.26"], "iso_description": "Contact with authorities and incident communication",
        "soc2_tsc": ["CC2.2"], "soc2_description": "Communication and Information - Stakeholder Sharing",
        "pci_dss": ["12.10.1"], "pci_description": "Communication plan for incidents",
        "ndpa": ["NDPA S.40"], "ndpa_description": "Communication to affected data subjects",
        "gdpr": ["Art. 34"], "gdpr_description": "Communication of breach to data subjects",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── RS.MI: Incident Mitigation (2) ─────────────────────────────────────────
    "RS.MI-01": {
        "nist_function": "RESPOND",
        "nist_description": "Incidents are contained.",
        "iso_27001": ["5.26"], "iso_description": "Response to information security incidents",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Containment",
        "pci_dss": ["12.10.1"], "pci_description": "Incident containment procedures",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Containment measures to limit breach impact",
        "gdpr": ["Art. 32"], "gdpr_description": "Ability to restore availability - containment",
        "status": "Not Assessed", "tier": "full",
    },
    "RS.MI-02": {
        "nist_function": "RESPOND",
        "nist_description": "Incidents are eradicated.",
        "iso_27001": ["5.26"], "iso_description": "Response to information security incidents - eradication",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Eradication",
        "pci_dss": ["12.10.1"], "pci_description": "Incident eradication procedures",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Eradication measures following breach containment",
        "gdpr": ["Art. 32"], "gdpr_description": "Remediation of vulnerability that caused breach",
        "status": "Not Assessed", "tier": "full",
    },
# ═══════════════════════════════════════════════════════════════════════
    # NIST CSF 2.0 - RECOVER FUNCTION - FULL EXPANSION (tier: full)
    # 7 additional subcategories (RC.RP-01 already core) - FINAL NIST BATCH
    # ═══════════════════════════════════════════════════════════════════════

    # ─── RC.RP: Incident Recovery Plan Execution (5 remaining) ────────────────
    "RC.RP-02": {
        "nist_function": "RECOVER",
        "nist_description": "Recovery actions are selected, scoped, prioritized, and performed.",
        "iso_27001": ["5.29", "5.30"], "iso_description": "Information security during disruption and ICT readiness",
        "soc2_tsc": ["A1.2"], "soc2_description": "Availability - Recovery Action Planning",
        "pci_dss": ["12.10.4"], "pci_description": "Business continuity recovery procedures",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Ability to restore availability and access in a timely manner",
        "status": "Not Assessed", "tier": "full",
    },
    "RC.RP-03": {
        "nist_function": "RECOVER",
        "nist_description": "The integrity of backups and other restoration assets is verified before using them for restoration.",
        "iso_27001": ["8.13"], "iso_description": "Information backup integrity verification",
        "soc2_tsc": ["A1.2"], "soc2_description": "Availability - Backup Integrity Verification",
        "pci_dss": ["12.10.4"], "pci_description": "Backup integrity testing before restoration",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Regular testing of restoration effectiveness",
        "status": "Not Assessed", "tier": "full",
    },
    "RC.RP-04": {
        "nist_function": "RECOVER",
        "nist_description": "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms.",
        "iso_27001": ["5.29"], "iso_description": "Information security during disruption",
        "soc2_tsc": ["A1.1"], "soc2_description": "Availability - Post-Incident Operations",
        "pci_dss": ["12.10.4"], "pci_description": "Business continuity operational norms",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable",
        "status": "Not Assessed", "tier": "full",
    },
    "RC.RP-05": {
        "nist_function": "RECOVER",
        "nist_description": "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed.",
        "iso_27001": ["5.30"], "iso_description": "ICT readiness for business continuity",
        "soc2_tsc": ["A1.2"], "soc2_description": "Availability - Restoration Verification",
        "pci_dss": ["12.10.4"], "pci_description": "Verification of restored systems",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable",
        "gdpr": ["Art. 32"], "gdpr_description": "Verification of restored data integrity",
        "status": "Not Assessed", "tier": "full",
    },
    "RC.RP-06": {
        "nist_function": "RECOVER",
        "nist_description": "The end of incident recovery is declared based on criteria, and incident-related documentation is completed.",
        "iso_27001": ["5.27"], "iso_description": "Learning from information security incidents",
        "soc2_tsc": ["CC7.5"], "soc2_description": "Incident Response - Closure Documentation",
        "pci_dss": ["12.10.6"], "pci_description": "Post-incident documentation and lessons learned",
        "ndpa": ["NDPA S.39"], "ndpa_description": "Breach documentation for NDPC records",
        "gdpr": ["Art. 33"], "gdpr_description": "Documentation of breach and remedial action taken",
        "status": "Not Assessed", "tier": "full",
    },

    # ─── RC.CO: Incident Recovery Communication (2) ────────────────────────────
    "RC.CO-03": {
        "nist_function": "RECOVER",
        "nist_description": "Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders.",
        "iso_27001": ["5.26"], "iso_description": "Response to information security incidents - stakeholder updates",
        "soc2_tsc": ["CC2.2"], "soc2_description": "Communication and Information - Recovery Updates",
        "pci_dss": ["12.10.1"], "pci_description": "Recovery status communication plan",
        "ndpa": ["NDPA S.40"], "ndpa_description": "Recovery status communication to affected parties",
        "gdpr": ["Art. 34"], "gdpr_description": "Communication of remediation progress to data subjects",
        "status": "Not Assessed", "tier": "full",
    },
    "RC.CO-04": {
        "nist_function": "RECOVER",
        "nist_description": "Public updates on incident recovery are shared using approved methods and messaging.",
        "iso_27001": ["5.26"], "iso_description": "Approved incident communication methods",
        "soc2_tsc": ["CC2.2"], "soc2_description": "Communication and Information - Public Messaging",
        "pci_dss": ["12.10.1"], "pci_description": "Approved public communication procedures",
        "ndpa": ["NDPA S.40"], "ndpa_description": "Public breach disclosure where required",
        "gdpr": ["Art. 34"], "gdpr_description": "Public communication for high-risk breaches affecting many data subjects",
        "status": "Not Assessed", "tier": "full",
    },
# ═══════════════════════════════════════════════════════════════════════
    # NDPA 2023 + GAID 2025 - DEEP EXPANSION (tier: full)
    # 6 additional controls covering previously unmapped sections
    # ═══════════════════════════════════════════════════════════════════════

    "NDPA.S29": {
        "nist_function": "GOVERN",
        "nist_description": "The organization fulfills its general obligations as a data controller or processor, including accountability for compliance, cooperation with the Nigeria Data Protection Commission, and maintaining evidence of compliance measures.",
        "iso_27001": ["5.1", "9.2"], "iso_description": "Leadership responsibility and internal audit for compliance evidence",
        "soc2_tsc": ["CC1.2"], "soc2_description": "Control Environment - Accountability",
        "pci_dss": ["12.1"], "pci_description": "Documented security policy and accountability",
        "ndpa": ["NDPA S.29"], "ndpa_description": "General obligations of data controller and data processor",
        "gdpr": ["Art. 24"], "gdpr_description": "Controller responsibility and accountability principle",
        "status": "Not Assessed", "tier": "full",
    },
    "NDPA.S30": {
        "nist_function": "PROTECT",
        "nist_description": "Sensitive personal data (health, biometric, genetic, financial, and similar special category data) is processed only under specific lawful grounds with heightened safeguards.",
        "iso_27001": ["5.34", "8.24"], "iso_description": "Privacy protection and cryptography for sensitive categories",
        "soc2_tsc": ["P4.1"], "soc2_description": "Privacy - Sensitive Data Handling",
        "pci_dss": ["3.4"], "pci_description": "Protection of sensitive stored data",
        "ndpa": ["NDPA S.30"], "ndpa_description": "Special safeguards for sensitive personal data processing",
        "gdpr": ["Art. 9"], "gdpr_description": "Processing of special categories of personal data",
        "status": "Not Assessed", "tier": "full",
    },
    "NDPA.S31": {
        "nist_function": "GOVERN",
        "nist_description": "Additional safeguards are applied when processing personal data of children or persons lacking legal capacity to consent, including parental or guardian consent mechanisms.",
        "iso_27001": ["5.34"], "iso_description": "Privacy protection for vulnerable data subjects",
        "soc2_tsc": ["P3.1"], "soc2_description": "Privacy - Consent for Vulnerable Populations",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["NDPA S.31"], "ndpa_description": "Processing of children's data and persons lacking legal capacity",
        "gdpr": ["Art. 8"], "gdpr_description": "Conditions applicable to child's consent",
        "status": "Not Assessed", "tier": "full",
    },
    "NDPA.S34": {
        "nist_function": "GOVERN",
        "nist_description": "Data subject rights under Part VI of the NDPA (access, correction, objection, restriction, erasure, and portability) are recognized, documented, and operationalized as a complete rights framework, not handled ad hoc.",
        "iso_27001": ["5.34"], "iso_description": "Comprehensive data subject rights framework",
        "soc2_tsc": ["P5.1", "P5.2"], "soc2_description": "Privacy - Complete Data Subject Rights",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["NDPA S.34"], "ndpa_description": "Rights of a data subject - Part VI framework",
        "gdpr": ["Art. 12", "Art. 15-22"], "gdpr_description": "Data subject rights framework (Chapter III)",
        "status": "Not Assessed", "tier": "full",
    },
    "NDPA.S44": {
        "nist_function": "GOVERN",
        "nist_description": "The organization has assessed whether it meets the 'data controller or processor of major importance' threshold under Section 44, triggering heightened registration, DPO, and audit obligations.",
        "iso_27001": ["4.1"], "iso_description": "Understanding organizational context and applicable obligations",
        "soc2_tsc": ["CC1.1"], "soc2_description": "Control Environment - Regulatory Classification",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["NDPA S.44"], "ndpa_description": "Definition and classification of data controller/processor of major importance",
        "gdpr": ["N/A"], "gdpr_description": "Not directly applicable (GDPR has no equivalent threshold classification)",
        "status": "Not Assessed", "tier": "full",
    },
    "GAID.ART6": {
        "nist_function": "GOVERN",
        "nist_description": "The organization has assessed whether any of its processing activities fall under the household or personal purpose exemption, and understands that this exemption does not excuse violations of a data subject's fundamental right to privacy.",
        "iso_27001": ["4.3"], "iso_description": "Determining the scope of the information security management system",
        "soc2_tsc": ["CC1.1"], "soc2_description": "Control Environment - Scope Determination",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["GAID Art. 6", "NDPA S.3"], "ndpa_description": "Household/personal purpose exemption scope and limits",
        "gdpr": ["Art. 2"], "gdpr_description": "Material scope - household activity exemption",
        "status": "Not Assessed", "tier": "full",
    },
# ═══════════════════════════════════════════════════════════════════════
    # GDPR - DEEP EXPANSION (tier: full)
    # 6 additional controls covering previously unmapped articles
    # ═══════════════════════════════════════════════════════════════════════

    "GDPR.A9": {
        "nist_function": "PROTECT",
        "nist_description": "Processing of special categories of personal data (health, biometric, genetic, racial, religious, political, sexual orientation) is prohibited by default and only permitted under specific listed exceptions.",
        "iso_27001": ["5.34", "8.24"], "iso_description": "Privacy protection and cryptography for special categories",
        "soc2_tsc": ["P4.1"], "soc2_description": "Privacy - Special Category Data",
        "pci_dss": ["3.4"], "pci_description": "Protection of sensitive stored data",
        "ndpa": ["NDPA S.30"], "ndpa_description": "Special safeguards for sensitive personal data",
        "gdpr": ["Art. 9"], "gdpr_description": "Processing of special categories of personal data - prohibited unless exception applies",
        "status": "Not Assessed", "tier": "full",
    },
    "GDPR.A16": {
        "nist_function": "GOVERN",
        "nist_description": "Processes exist to correct inaccurate personal data without undue delay and to complete incomplete personal data, including by means of a supplementary statement.",
        "iso_27001": ["5.34"], "iso_description": "Data accuracy and correction processes",
        "soc2_tsc": ["P5.2"], "soc2_description": "Privacy - Data Subject Rights (Rectification)",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["NDPA S.34"], "ndpa_description": "Right to rectification under data subject rights framework",
        "gdpr": ["Art. 16"], "gdpr_description": "Right to rectification of inaccurate personal data",
        "status": "Not Assessed", "tier": "full",
    },
    "GDPR.A21": {
        "nist_function": "GOVERN",
        "nist_description": "Data subjects can object to processing based on legitimate interests or public task grounds, and processing must stop unless compelling legitimate grounds override the objection. Objection to direct marketing must always be honored.",
        "iso_27001": ["5.34"], "iso_description": "Handling data subject objections",
        "soc2_tsc": ["P5.2"], "soc2_description": "Privacy - Data Subject Rights (Objection)",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["NDPA S.34"], "ndpa_description": "Right to object under data subject rights framework",
        "gdpr": ["Art. 21"], "gdpr_description": "Right to object, absolute for direct marketing",
        "status": "Not Assessed", "tier": "full",
    },
    "GDPR.A22": {
        "nist_function": "GOVERN",
        "nist_description": "Data subjects are not subject to decisions based solely on automated processing, including profiling, which produce legal or similarly significant effects, unless specific conditions and safeguards apply.",
        "iso_27001": ["5.34"], "iso_description": "Governance of automated decision-making systems",
        "soc2_tsc": ["P3.1"], "soc2_description": "Privacy - Automated Decision Governance",
        "pci_dss": ["N/A"], "pci_description": "Not directly applicable",
        "ndpa": ["N/A"], "ndpa_description": "Not directly applicable (NDPA has no direct equivalent provision)",
        "gdpr": ["Art. 22"], "gdpr_description": "Automated individual decision-making, including profiling",
        "status": "Not Assessed", "tier": "full",
    },
    "GDPR.A28": {
        "nist_function": "GOVERN",
        "nist_description": "Processing by a processor is governed by a contract or legal act binding the processor to the controller, setting out subject matter, duration, nature, purpose of processing, and the processor's obligations.",
        "iso_27001": ["5.20"], "iso_description": "Addressing information security within supplier agreements",
        "soc2_tsc": ["CC9.2"], "soc2_description": "Risk Mitigation - Processor Contractual Obligations",
        "pci_dss": ["12.8.2"], "pci_description": "Written agreements with service providers",
        "ndpa": ["NDPA S.42"], "ndpa_description": "Data protection clauses in processor contracts",
        "gdpr": ["Art. 28"], "gdpr_description": "Processor obligations under a binding data processing agreement",
        "status": "Not Assessed", "tier": "full",
    },
    "GDPR.A34": {
        "nist_function": "RESPOND",
        "nist_description": "When a personal data breach is likely to result in a high risk to the rights and freedoms of natural persons, the controller communicates the breach to the affected data subjects without undue delay, in clear and plain language.",
        "iso_27001": ["5.26"], "iso_description": "Response to information security incidents - data subject communication",
        "soc2_tsc": ["CC7.4"], "soc2_description": "Incident Response - Data Subject Notification",
        "pci_dss": ["12.10.1"], "pci_description": "Breach communication procedures",
        "ndpa": ["NDPA S.40"], "ndpa_description": "Notification to data subjects following a breach",
        "gdpr": ["Art. 34"], "gdpr_description": "Communication of a personal data breach to the data subject",
        "status": "Not Assessed", "tier": "full",
    },
}


def list_all_controls():
    print("\n" + "="*70)
    print("ALL CONTROLS IN DATABASE")
    print("="*70)
    functions = {}
    for control_id, details in CONTROLS_DB.items():
        func = details["nist_function"]
        if func not in functions:
            functions[func] = []
        functions[func].append(control_id)
    for func, controls in functions.items():
        print(f"\n[ {func} ]")
        for control_id in controls:
            desc = CONTROLS_DB[control_id]["nist_description"]
            print(f"  {control_id}: {desc[:65]}...")


def lookup_control(control_id):
    control_id = control_id.upper()
    if control_id not in CONTROLS_DB:
        print(f"\nControl '{control_id}' not found. Type 'list' to see all.")
        return
    c = CONTROLS_DB[control_id]
    print("\n" + "="*70)
    print(f"CONTROL: {control_id}")
    print("="*70)
    print(f"NIST Function : {c['nist_function']}")
    print(f"Description   : {c['nist_description']}")
    print(f"\nISO 27001     : {', '.join(c['iso_27001'])} - {c['iso_description']}")
    print(f"SOC 2 TSC     : {', '.join(c['soc2_tsc'])} - {c['soc2_description']}")
    print(f"PCI-DSS       : {', '.join(c['pci_dss'])} - {c['pci_description']}")
    print(f"NDPA/GAID     : {', '.join(c['ndpa'])} - {c['ndpa_description']}")
    print(f"\nStatus        : {c['status']}")


def update_control_status(control_id, new_status):
    control_id = control_id.upper()
    valid_statuses = ["Not Assessed", "Compliant", "Partial", "Non-Compliant"]
    if control_id not in CONTROLS_DB:
        print(f"Control '{control_id}' not found.")
        return
    if new_status not in valid_statuses:
        print(f"Invalid status. Choose from: {', '.join(valid_statuses)}")
        return
    CONTROLS_DB[control_id]["status"] = new_status
    print(f"Updated {control_id} status to: {new_status}")


def generate_report():
    today = datetime.date.today().strftime("%Y-%m-%d")
    filename = f"compliance_report_{today}.csv"
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Control ID", "NIST Function", "NIST Description",
            "ISO 27001", "ISO Detail",
            "SOC 2 TSC", "SOC 2 Detail",
            "PCI-DSS", "PCI Detail",
            "NDPA/GAID", "NDPA Detail",
            "Status"
        ])
        for control_id, details in CONTROLS_DB.items():
            writer.writerow([
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
                details["status"]
            ])
            summary[details["status"]] += 1
    print(f"\nReport saved: {filename}")
    for status, count in summary.items():
        print(f"  {status}: {count} controls")


def show_by_function(nist_function):
    nist_function = nist_function.upper()
    valid_functions = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    if nist_function not in valid_functions:
        print(f"Invalid function. Choose from: {', '.join(valid_functions)}")
        return
    print(f"\n[ Controls under NIST CSF: {nist_function} ]")
    found = False
    for control_id, details in CONTROLS_DB.items():
        if details["nist_function"] == nist_function:
            found = True
            print(f"\n  {control_id}")
            print(f"  NIST     : {details['nist_description']}")
            print(f"  ISO      : {', '.join(details['iso_27001'])}")
            print(f"  SOC2     : {', '.join(details['soc2_tsc'])}")
            print(f"  PCI-DSS  : {', '.join(details['pci_dss'])}")
            print(f"  NDPA/GAID: {', '.join(details['ndpa'])}")
            print(f"  Status   : {details['status']}")
    if not found:
        print("No controls found for that function.")


def main():
    print("\n" + "="*70)
    print("  COMPLIANCE CROSS-REFERENCE MAPPER")
    print("  NIST CSF 2.0 | ISO 27001:2022 | SOC 2 | PCI-DSS v4.0.1| NDPA 2023 + GAID 2025")
    print("="*70)
    while True:
        print("\nCOMMANDS:")
        print("  list             - Show all controls")
        print("  lookup <ID>      - Look up a control")
        print("  function <NAME>  - Filter by NIST function")
        print("  update <ID>      - Update control status")
        print("  report           - Generate CSV report")
        print("  exit             - Quit")
        user_input = input("\n> ").strip()
        parts = user_input.split()
        if not parts:
            continue
        command = parts[0].lower()
        if command == "exit":
            print("Exiting. Good work.")
            break
        elif command == "list":
            list_all_controls()
        elif command == "lookup":
            if len(parts) < 2:
                print("Usage: lookup <CONTROL_ID>")
            else:
                lookup_control(parts[1])
        elif command == "function":
            if len(parts) < 2:
                print("Usage: function <NAME>")
            else:
                show_by_function(parts[1])
        elif command == "update":
            if len(parts) < 2:
                print("Usage: update <CONTROL_ID>")
            else:
                print("Select new status:")
                print("  1. Compliant  2. Partial  3. Non-Compliant  4. Not Assessed")
                choice = input("Enter number: ").strip()
                status_map = {"1":"Compliant","2":"Partial","3":"Non-Compliant","4":"Not Assessed"}
                if choice in status_map:
                    update_control_status(parts[1], status_map[choice])
                else:
                    print("Invalid choice.")
        elif command == "report":
            generate_report()
        else:
            print(f"Unknown command: '{command}'.")


if __name__ == "__main__":
    main()

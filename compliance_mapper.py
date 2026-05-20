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

Author: [Your Name]
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

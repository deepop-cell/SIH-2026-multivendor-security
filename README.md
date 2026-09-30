# Multivendor Security Model Prototype - SIH Submission

An automated security policy compliance and audit framework for heterogeneous multi-vendor network and cloud environments.

## Architecture & Workflow
- **Data Ingestion (`ingest.py`):** Collects configuration dumps and telemetry from multiple vendor environments into normalized JSON formats (`input.json`).
- **Policy Engine (OPA & Rego - `rules.rego`):** Evaluates ingested configs against standardized security baselines and unified compliance rules.
- **Translation Layer (`translator.py`):** Translates multi-vendor specific syntax into declarative OPA queries.
- **Audit & Reporting (`report.py`):** Generates automated compliance logs and audit summaries (`Final_Audit.pdf`).
- **Dashboard (`dashboard.py`):** Centralized visualization interface for tracking policy violations across vendors.

## Local Prototype Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/girisoumyadeep101/SIH-2026-multivendor-security.git](https://github.com/girisoumyadeep101/SIH-2026-multivendor-security.git)
   cd SIH-2026-multivendor-security

   Download Open Policy Agent (opa) and place the executable in the project root.

Run the dashboard:

Bash
python dashboard.py

Development Roadmap
[x] Multi-vendor config normalization pipeline (Localhost)

[x] OPA / Rego policy baseline validation

[ ] Real-time API telemetry connectors (Cisco, Fortinet, AWS)

[ ] Automated remediation playbooks

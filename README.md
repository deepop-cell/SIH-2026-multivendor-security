# Multivendor Security Model Prototype - SIH Submission

An automated security policy compliance and audit framework for heterogeneous multi-vendor network and cloud environments.

## Architecture & Workflow
- Data Ingestion (ingest.py): Collects configuration dumps and telemetry from multiple vendor environments into normalized JSON formats.
- Policy Engine (OPA & Rego): Evaluates ingested configs against standardized security baselines and unified compliance rules.
- Translation Layer (translator.py): Translates multi-vendor specific syntax into declarative OPA queries.
- Audit & Reporting (report.py): Generates automated compliance logs and audit summaries.
- Dashboard (dashboard.py): Centralized visualization interface for tracking policy violations across vendors.

## Local Prototype Setup
1. Clone the repository:
git clone https://github.com/girisoumyadeep101/SIH-2026-multivendor-security.git
cd SIH-2026-multivendor-security

2. Download Open Policy Agent (opa) and place the executable in the project root.

3. Run the dashboard:
python dashboard.py

## Development Roadmap
- [x] Multi-vendor config normalization pipeline (Localhost)
- [x] OPA / Rego policy baseline validation
- [ ] Real-time API telemetry connectors (Cisco, Fortinet, AWS)
- [ ] Automated remediation playbooks

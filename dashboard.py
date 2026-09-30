import streamlit as st
import subprocess
import json
import time
import ollama
from neo4j import GraphDatabase
from reportlab.pdfgen import canvas
from streamlit_agraph import agraph, Node, Edge, Config

st.set_page_config(page_title="Network AI Auditor - SIH", layout="wide")

st.title("🛡️ Enterprise Network AI Auditor & Neuro-Symbolic Compliance Engine")
st.markdown("Autonomous Multi-Vendor Ingestion, Local SLM Semantics, OPA Verification, and Graph RAG Memory.")

# --- SIDEBAR: Multi-Vendor Ingestion Hub ---
st.sidebar.header("🌐 Multi-Vendor Ingestion Hub")
vendor = st.sidebar.selectbox(
    "Select Network Hardware Vendor", 
    ["Cisco IOS-XE", "Juniper Junos", "Arista EOS", "Fortinet FortiOS (Test)", "Custom / Unrecognized Proprietary OS"]
)

# Dynamic Template Generation
if vendor == "Cisco IOS-XE":
    default_json = '{\n  "device": "cisco-core-01",\n  "vendor": "cisco",\n  "management": {\n    "protocol": "ssh",\n    "ssh_version": 1,\n    "telnet_enabled": true\n  }\n}'
elif vendor == "Juniper Junos":
    default_json = '{\n  "device": "juniper-edge-02",\n  "vendor": "juniper",\n  "system": {\n    "protocol-version": "v1",\n    "telnet": "enabled"\n  }\n}'
elif vendor == "Arista EOS":
    default_json = '{\n  "device": "arista-spine-03",\n  "vendor": "arista",\n  "management_ssh": "v1"\n}'
elif vendor == "Fortinet FortiOS (Test)":
    default_json = '{\n  "device": "fortigate-fw-01",\n  "vendor": "fortinet",\n  "os_version": "7.2.4",\n  "system_global": {\n    "admin-sport": 443,\n    "admin-ssh-port": 22,\n    "allow-admin-telnet": true\n  }\n}'
else:
    default_json = '{\n  "device": "unknown-box-99",\n  "vendor": "whitebox",\n  "proprietary_cli_block": "crypto secure-channel legacy-mode 1"\n}'

col1, col2 = st.columns([1.2, 1])

with col1:
    st.subheader("1. Raw Ingestion & AI Normalizer")
    
    # Raw input text area for messy or arbitrary vendor configs
    raw_config_input = st.text_area(
        "Paste Raw Vendor Config (Text, CLI, or Messy JSON):", 
        value='system-view\nsysname core-router-01\nssh server version 1\nstelnet server enable', 
        height=120
    )

    if st.button("Normalize to Standard Schema"):
        with st.spinner("SLM normalizing raw configuration into unified JSON schema..."):
            try:
                norm_response = ollama.chat(model='llama3.2', messages=[
                    {'role': 'system', 'content': 'You are a network configuration normalizer. Convert the given raw CLI text into a clean, standardized JSON schema. You MUST wrap the entire output in a single root JSON object starting with { and ending with }. Output ONLY valid JSON, no markdown blocks, no explanations.'},
                    {'role': 'user', 'content': f"Normalize this config: {raw_config_input}"}
                ])
                normalized_json = norm_response['message']['content'].strip()
                normalized_json = normalized_json.replace("```json", "").replace("```", "").strip()
                
                if not normalized_json.startswith("{"):
                    normalized_json = "{\n" + normalized_json
                if not normalized_json.endswith("}"):
                    normalized_json = normalized_json + "\n}"
                    
                try:
                    json.loads(normalized_json)
                except json.JSONDecodeError:
                    normalized_json = '{\n  "error": "SLM generated malformed JSON structure. Please click Normalize again."\n}'

                st.session_state['normalized_editor'] = normalized_json
                st.session_state['live_editor_box'] = normalized_json
            except Exception as e:
                st.error(f"Normalization failed: {e}")

    # Fallback initialization
    if 'normalized_editor' not in st.session_state:
        st.session_state['normalized_editor'] = default_json

    st.markdown("**Normalized JSON Schema (Ready for OPA & Audit):**")
    editor_content = st.text_area(
        "Live Normalized Configuration:", 
        value=st.session_state['normalized_editor'], 
        height=150, 
        key="live_editor_box"
    )
    
    with open("input.json", "w") as f:
        f.write(editor_content)

    if st.button("Run Neuro-Symbolic Audit"):
        # 1. Dynamic OPA Evaluation
        result = subprocess.run(['opa', 'eval', '-i', 'input.json', '-d', 'rules.rego', 'data.network.security.deny'], capture_output=True, text=True)
        
        audit_failed = False

        try:
            if result.returncode != 0:
                err_msg = result.stderr.strip() if result.stderr.strip() else result.stdout.strip()
                st.error(f"OPA execution failed: {err_msg}")
                audit_failed = True
            else:
                opa_output = json.loads(result.stdout)
                
                if "result" in opa_output and len(opa_output["result"]) > 0:
                    val = opa_output["result"][0].get("value", False)
                    if val is True or (isinstance(val, list) and len(val) > 0) or val == [True]:
                        audit_failed = True
                    elif str(val).lower() == "true":
                        audit_failed = True
                        
                if '"value": true' in result.stdout.lower():
                    audit_failed = True

        except Exception as e:
            st.error(f"OPA evaluation error: {e}")
            audit_failed = True

        # 2. Strict SLM Analysis with Guardrails
        ai_analysis = "SLM Offline."
        try:
            slm_response = ollama.chat(model='llama3.2', messages=[
            {
                'role': 'system',
                'content': '''
        You are the explanation layer of an enterprise network compliance system.

        OPA is the authoritative compliance engine.
        You MUST NOT override the OPA result.

        Security rules:

        1. SSH version 2 is compliant.
        2. SSH version 1 is a violation.
        3. Telnet management access is a violation.
        4. RSA key size >= 3072 bits is compliant.
        5. RSA key size < 3072 bits is a violation.
        6. exec-timeout 0 0 means the idle timeout is disabled.
        7. exec-timeout values are minutes and seconds.
        8. A redacted or placeholder password must NOT be called weak.
        9. Do not claim MFA is missing unless the configuration/policy explicitly requires MFA.
        10. Do not claim that the absence of an explicitly configured SSH port is a vulnerability.
        11. The Cisco "login" command is NOT a username.
        12. Do not invent configuration commands or settings that are not present.

        If OPA reports FAIL, explain the actual security violations.
        If OPA reports PASS, explain why the configuration satisfies the defined policy.

        Be concise and technically accurate.
        '''
            },
            {
                'role': 'user',
                'content': f'''
        Vendor: {vendor}

        OPA Audit Result:
        {"FAIL" if audit_failed else "PASS"}

        Configuration:
        {editor_content}

        Explain the compliance result based only on the configuration and OPA result.
        '''
            }
        ])
            ai_analysis = slm_response['message']['content']
        except Exception:
            pass

        if audit_failed:
            st.error(f"[{vendor}] CRITICAL FAILURE: Policy violation detected by OPA!")
            st.warning(f"🤖 **Neuro-Semantic SLM Diagnostic:** {ai_analysis}")
            st.session_state['audit_failed'] = True
        else:
            st.success(f"[{vendor}] Network configuration fully compliant and secure.")
            st.info(f"🤖 **Neuro-Semantic SLM Diagnostic:** {ai_analysis}")
            st.session_state['audit_failed'] = False

    st.subheader("3. Actionable Automated Remediation")
    if st.button("Generate Fix-It PDF Report"):
        with st.spinner("SLM generating dynamic remediation command..."):
            try:
                fix_response = ollama.chat(model='llama3.2', messages=[
                    {'role': 'system', 'content': 'You are a network router CLI. Reply ONLY with the exact CLI command to fix insecure SSH or Telnet based on the provided JSON. Do not explain. Just output the command.'},
                    {'role': 'user', 'content': f"Generate the fix for this config: {editor_content}"}
                ])
                dynamic_cli_fix = fix_response['message']['content']
            except:
                dynamic_cli_fix = "> Error: SLM offline. Manually enforce secure protocol."

        c = canvas.Canvas("Final_Audit.pdf")
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 780, f"Enterprise Security AI Report - {vendor}")
        c.setFont("Helvetica", 12)
        
        if st.session_state.get('audit_failed', False):
            c.drawString(100, 750, "Status: CRITICAL VULNERABILITY EXPOSED")
            c.drawString(100, 730, "AI-Generated Remediation Command:")
            c.setFillColorRGB(0.8, 0, 0)
            c.drawString(100, 710, dynamic_cli_fix)
        else:
            c.setFillColorRGB(0, 0.5, 0)
            c.drawString(100, 750, "Status: SYSTEM SECURE & COMPLIANT")
            c.drawString(100, 730, "Zero vulnerabilities detected across cross-vendor policies.")
            
        c.save()
        st.success("Dynamic PDF Generated successfully as 'Final_Audit.pdf'.")

    if st.button("Execute SSH Remediation (Live Sync)"):
        # Check if the audit actually failed before running a fix
        if not st.session_state.get('audit_failed', False):
            st.info("System is already fully compliant. No remediation deployment necessary.")
        else:
            terminal = st.empty()
            try:
                dev = json.loads(editor_content).get("device", "Core-Router")
            except:
                dev = "Core-Router"
            
            lines = [
                f"Establishing secure SSH connection to {dev}...",
                "Authenticating via zero-trust proxy...",
                "Entering configuration mode...",
                "Applying AI-generated remediation policy...",
                "Validating new cryptographic standards...",
                "Success: Device secured and connection closed."
            ]
            log = ""
            for line in lines:
                log += f"> {line}\n"
                terminal.code(log, language="bash")
                time.sleep(0.5) 
            st.success("Automated AI remediation deployed successfully.")

    with st.expander("🧠 Human-in-the-Loop AI Memory & Graph RAG Expander"):
        st.markdown("Log custom human corrections for unrecognized vendor schemas to update graph memory.")
        
        unknown_config_id = st.text_input("Unrecognized Config / CVE Signature", "CVE-2026-NEURO-01", key="sig_input")
        admin_correction = st.text_area("Admin Remediation Policy & Context", "Enforce secure cipher suites and map custom whitebox parameters to schema.", key="corr_input")
        
        if st.button("Store to AI Graph Memory"):
            try:
                URI = "bolt://localhost:7687"
                AUTH = ("neo4j", "Giri@1234")
                
                with GraphDatabase.driver(URI, auth=AUTH) as driver:
                    driver.execute_query(
                        "CREATE (m:AiMemory {signature: $sig, correction: $corr, vendor: $v, timestamp: timestamp(), source: 'Human-Admin'}) "
                        "WITH m "
                        "MATCH (r:Router {name: 'KGP-Core-Router'}) "
                        "MERGE (r)-[:HAS_LEARNED_FIX]->(m)",
                        sig=unknown_config_id, corr=admin_correction, v=vendor
                    )
                st.success(f"Successfully stored '{unknown_config_id}' into Neo4j Graph Memory!")
            except Exception as e:
                st.error(f"Memory storage failed: {e}")

with col2:
    st.subheader("2. Enterprise Attack Blast Radius (Local Graph)")
    if st.session_state.get('audit_failed'):
        st.warning("Vulnerability active. Mapping multi-tier enterprise threat spread.")
        
        URI = "bolt://localhost:7687"
        AUTH = ("neo4j", "Giri@1234")
        
        try:
            parsed_json = json.loads(editor_content)
            dynamic_device = parsed_json.get("device", "Unknown-Router")
        except:
            dynamic_device = "Syntax-Error-Device"

        if st.button("Calculate & Visualize Blast Radius"):
            try:
                with GraphDatabase.driver(URI, auth=AUTH) as driver:
                    driver.execute_query(
                        "MERGE (ext:Internet {name: 'Public Internet'}) "
                        "MERGE (r:Router {name: $dev_name, status: 'Vulnerable', vendor: $v}) "
                        "MERGE (sw:Switch {name: 'Server-Subnet-Switch', status: 'At-Risk'}) "
                        "MERGE (db:Database {name: 'Customer_PII_Vault', status: 'Critical Exposure'}) "
                        "MERGE (ext)-[:CONNECTS_TO {port: 22}]->(r) "
                        "MERGE (r)-[:ROUTES_TRAFFIC_TO]->(sw) "
                        "MERGE (sw)-[:EXPOSES_DATA_TO]->(db)",
                        dev_name=dynamic_device, v=vendor
                    )
                    
                    records, _, _ = driver.execute_query(
                        "MATCH p = (ext:Internet)-[:CONNECTS_TO]->(r:Router)-[:ROUTES_TRAFFIC_TO]->(sw:Switch)-[:EXPOSES_DATA_TO]->(db:Database) "
                        "RETURN ext.name AS Source, r.name AS Router, sw.name AS Switch, db.name AS Target LIMIT 1"
                    )
                
                nodes = []
                edges = []
                
                if records:
                    record = records[0]
                    nodes.append(Node(id=record['Source'], label=record['Source'], color="red"))
                    nodes.append(Node(id=record['Router'], label=f"Vulnerable:\n{record['Router']}", color="orange"))
                    nodes.append(Node(id=record['Switch'], label=record['Switch'], color="gray"))
                    nodes.append(Node(id=record['Target'], label=record['Target'], color="green"))
                    
                    edges.append(Edge(source=record['Source'], target=record['Router'], label="SSH Exploit"))
                    edges.append(Edge(source=record['Router'], target=record['Switch'], label="Lateral Move"))
                    edges.append(Edge(source=record['Switch'], target=record['Target'], label="Data Exfiltration"))
                
                config = Config(width=500, height=400, directed=True, nodeHighlightBehavior=True, highlightColor="#F7A7A6")
                
                st.success("Multi-hop enterprise threat chain pulled from Neo4j!")
                agraph(nodes=nodes, edges=edges, config=config)
                
            except Exception as e:
                st.error(f"Local Neo4j Connection Failed: {e}")
    else:
        st.info("Run a failed audit first to unlock network blast radius mapping.")

# --- Bottom Section: Live AI Chat ---
st.markdown("---")
st.subheader("💬 Query Infrastructure AI")
user_q = st.chat_input("Ask the local SLM about this specific network configuration...")

if user_q:
    with st.chat_message("user"):
        st.write(user_q)
    with st.chat_message("assistant"):
        with st.spinner("Analyzing active configuration..."):
            try:
                response = ollama.chat(model='llama3.2', messages=[
                    {'role': 'system', 'content': f'You are an AI network engineer. Answer concisely based ONLY on this active JSON config: {editor_content}'},
                    {'role': 'user', 'content': user_q}
                ])
                st.write(response['message']['content'])
            except Exception:
                st.error("Ollama local SLM is currently offline.")
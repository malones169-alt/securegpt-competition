import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import os
import json
from datetime import datetime

load_dotenv()
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

st.set_page_config(page_title="SecureGPT", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main-header {font-size: 3rem; font-weight: bold; color: #1f77b4; text-align: center; padding: 1rem;}
.sub-header {font-size: 1.2rem; color: #666; text-align: center; margin-bottom: 2rem;}
</style>
""", unsafe_allow_html=True)

if 'history' not in st.session_state:
    st.session_state.history = []

st.markdown('<p class="main-header">🛡️ SecureGPT</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">AI-Powered Security Incident Response Assistant</p>', unsafe_allow_html=True)

st.sidebar.title("Analysis Type")
analysis_type = st.sidebar.selectbox("Choose:", ["🚨 Incident Analysis", "📧 Phishing Detection", "📊 Log Analysis"])

col1, col2 = st.columns([2, 1])

with col1:
    st.subheader(analysis_type)
    
    if "Incident" in analysis_type:
        st.markdown("### 📝 Incident Details")
# SAMPLE INCIDENTS
        with st.expander("💡 Load Sample Incident", expanded=False):
            sample_incidents = {
                "Ransomware Attack": {
                    "description": "User workstation DESKTOP-W10-045 infected with ransomware at 14:30 UTC. All files encrypted with .locked extension. Ransom note 'HOW_TO_DECRYPT.txt' demands 5 Bitcoin within 48 hours. Network logs show initial connection to suspicious IP 185.220.101.45 on port 4444. Process tree shows powershell.exe spawning cmd.exe and vssadmin.exe (shadow copy deletion). User Jane.Smith reported receiving phishing email with invoice.pdf.exe attachment 30 minutes prior to encryption.",
                    "severity": "Critical"
                },
                "PowerShell C2 Beacon": {
                    "description": "EDR alert triggered on LAPTOP-SALES-012 for encoded PowerShell execution at 09:15 UTC. Base64 decoded command reveals download cradle from hxxp://malicious-domain[.]tk/payload.ps1. Process established persistent outbound HTTPS connections to 203.0.113.42:443 every 60 seconds (beacon pattern). Suspicious scheduled task 'WindowsUpdateCheck' created. No user activity at time of execution. Memory dump shows Cobalt Strike indicators.",
                    "severity": "High"
                },
                "Lateral Movement Detected": {
                    "description": "Multiple failed authentication attempts detected from compromised account SERVICE_ADMIN across 15 workstations in 10-minute window (09:30-09:40 UTC). Successful logon to HR-FILE-SERVER using pass-the-hash technique. PsExec.exe executed remotely on three systems (HR-WKS-001, HR-WKS-003, HR-WKS-007). Mimikatz indicators found in memory. Admin share access (C$) from unusual source IP 10.50.25.89. Account last legitimate use was 2 weeks ago.",
                    "severity": "Critical"
                },
                "Phishing with Credential Harvesting": {
                    "description": "User reported suspicious Office365 login page after clicking link in email from CEO-impostor@company-portal[.]com. Email claimed urgent password reset required. Fake login page hosted at hxxps://office365-secure-login[.]xyz captured credentials. User credentials subsequently used to access mailbox from IP 198.51.100.22 (Nigeria). 250 emails forwarded to external address. MFA not enabled on account.",
                    "severity": "High"
                },
                "Data Exfiltration via DNS": {
                    "description": "Abnormal DNS query volume detected from database server DB-PROD-01 (45,000 queries in 1 hour vs normal 500/hour). Queries to various subdomains of exfil-server[.]com containing hex-encoded data. Analysis shows customer PII being exfiltrated via DNS tunneling. Malicious cron job discovered: /tmp/.hidden_script executing every 5 minutes. Initial access vector: compromised SSH key for service account.",
                    "severity": "Critical"
                }
            }
            
            sample_choice = st.selectbox(
                "Select a sample incident:",
                [""] + list(sample_incidents.keys())
            )
            
            if sample_choice and st.button("📋 Load Sample", use_container_width=True):
                st.session_state.sample_title = sample_choice
                st.session_state.sample_description = sample_incidents[sample_choice]["description"]
                st.session_state.sample_severity = sample_incidents[sample_choice]["severity"]
                st.rerun()
        
        # Text inputs with sample data if loaded
        title = st.text_input(
            "Incident Title", 
            value=st.session_state.get('sample_title', ''),
            placeholder="e.g., Suspicious PowerShell"
        )
        description = st.text_area(
            "Describe the incident:", 
            value=st.session_state.get('sample_description', ''),
            placeholder="Details...", 
            height=150
        )
        title = st.text_input("Incident Title", placeholder="e.g., Suspicious PowerShell")
        description = st.text_area("Describe the incident:", placeholder="Details...", height=150)
        files = st.file_uploader("Upload evidence (optional)", accept_multiple_files=True, type=['txt','log','png','jpg','csv'])
        severity = st.selectbox("Severity", ["Unknown", "Low", "Medium", "High", "Critical"])
index=["Unknown", "Low", "Medium", "High", "Critical"].index(st.session_state.get('sample_severity', 'Unknown'))
        
        
    if st.button("🔍 Analyze Incident", type="primary", use_container_width=True):
            if description:
                with st.spinner("🤖 Analyzing..."):
                    prompt = "You are a Senior SOC Analyst. Analyze this incident:\n\n"
                    prompt += f"Title: {title}\nSeverity: {severity}\nDescription: {description}\n\n"
                    prompt += "Provide: 1) Executive Summary 2) Assessment 3) MITRE ATT&CK 4) IOCs 5) Response Actions 6) Queries 7) Remediation 8) Timeline"
                    
                    try:
                        model = genai.GenerativeModel('gemini-2.5-flash')
                        content = [prompt]
                        
                        if files:
                            for f in files:
                                if f.type in ['image/png', 'image/jpeg']:
                                    content.append({'mime_type': f.type, 'data': f.getvalue()})
                                else:
                                    content.append(f"\n\nFILE: {f.name}\n{f.getvalue().decode('utf-8', errors='ignore')[:5000]}")
                        
                        response = model.generate_content(content)
                        st.success("✅ Analysis Complete!")
                        st.markdown("---")
                        st.markdown(response.text)
                        # IOC EXTRACTION
                        st.markdown("---")
                        st.subheader("🔍 Extracted IOCs")
                        
                        import re
                        
                        # Extract IOCs
                        iocs = {
                            'ips': list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', response.text))),
                            'domains': list(set(re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', response.text.lower()))),
                            'md5': list(set(re.findall(r'\b[a-f0-9]{32}\b', response.text.lower()))),
                            'sha256': list(set(re.findall(r'\b[a-f0-9]{64}\b', response.text.lower())))
                        }
                        
                        col_ioc1, col_ioc2, col_ioc3, col_ioc4 = st.columns(4)
                        
                        with col_ioc1:
                            st.metric("IP Addresses", len(iocs['ips']))
                            if iocs['ips']:
                                for ip in iocs['ips']:
                                    st.code(ip)
                        
                        with col_ioc2:
                            st.metric("Domains", len(iocs['domains']))
                            if iocs['domains']:
                                for domain in iocs['domains'][:5]:
                                    st.code(domain)
                        
                        with col_ioc3:
                            st.metric("MD5 Hashes", len(iocs['md5']))
                            if iocs['md5']:
                                for hash in iocs['md5']:
                                    st.code(hash[:16] + "...")
                        
                        with col_ioc4:
                            st.metric("SHA256 Hashes", len(iocs['sha256']))
                            if iocs['sha256']:
                                for hash in iocs['sha256']:
                                    st.code(hash[:16] + "...")
                        
                        # Export IOCs as CSV
                        if any(iocs.values()):
                            ioc_csv = "Type,Value\n"
                            for ip in iocs['ips']:
                                ioc_csv += f"IP,{ip}\n"
                            for domain in iocs['domains']:
                                ioc_csv += f"Domain,{domain}\n"
                            for hash in iocs['md5']:
                                ioc_csv += f"MD5,{hash}\n"
                            for hash in iocs['sha256']:
                                ioc_csv += f"SHA256,{hash}\n"
                            
                            st.download_button(
                                "📥 Download IOCs (CSV)",
                                ioc_csv,
                                f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                "text/csv"
                            )
                        result = {'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'title': title, 'analysis': response.text}
                        st.session_state.history.append(result)
                        
                        st.markdown("---")
                        col_e1, col_e2 = st.columns(2)
                        with col_e1:
                            st.download_button("📄 Download TXT", response.text, f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                        with col_e2:
                            st.download_button("📊 Download JSON", json.dumps(result, indent=2), f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                    # SPLUNK QUERY GENERATOR
                        st.markdown("---")
                        st.subheader("🔎 Splunk Investigation Queries")
                        
                        with st.expander("📊 View Generated Splunk Queries", expanded=True):
                            queries = []
                            
                            # Query 1: Search for IPs
                            if iocs['ips']:
                                ip_list = " OR ".join([f'dest_ip="{ip}"' for ip in iocs['ips']])
                                queries.append({
                                    'name': 'Search for Suspicious IPs',
                                    'query': f'index=* ({ip_list})\n| stats count by src_ip, dest_ip, dest_port\n| sort -count'
                                })
                            
                            # Query 2: PowerShell activity
                            if 'powershell' in description.lower() or 'powershell' in response.text.lower():
                                queries.append({
                                    'name': 'PowerShell Execution Events',
                                    'query': 'index=windows EventCode=4688 process_name=*powershell.exe\n| table _time, Computer, User, CommandLine\n| sort -_time'
                                })
                                queries.append({
                                    'name': 'Encoded PowerShell Commands',
                                    'query': 'index=windows powershell (encodedcommand OR -enc OR -e)\n| table _time, Computer, User, CommandLine\n| sort -_time'
                                })
                            
                            # Query 3: Network connections
                            if iocs['ips']:
                                for ip in iocs['ips'][:3]:
                                    queries.append({
                                        'name': f'Network Connections to {ip}',
                                        'query': f'index=firewall OR index=proxy dest_ip="{ip}"\n| stats count by src_ip, dest_port, action\n| sort -count'
                                    })
                            
                            # Query 4: File creation/modification
                            if 'ransomware' in description.lower() or 'encrypted' in description.lower():
                                queries.append({
                                    'name': 'File Modification Activity',
                                    'query': 'index=windows EventCode=4663 Object_Type=File\n| stats count by Computer, Object_Name, Process_Name\n| where count > 100\n| sort -count'
                                })
                            
                            # Query 5: Process execution timeline
                            queries.append({
                                'name': 'Process Execution Timeline',
                                'query': f'index=windows EventCode=4688 Computer="*"\n| table _time, Computer, Process_Name, Process_Command_Line, Parent_Process_Name\n| sort _time'
                            })
                            
                            # Display queries
                            for i, q in enumerate(queries, 1):
                                st.markdown(f"**{i}. {q['name']}**")
                                st.code(q['query'], language='spl')
                                st.markdown("")
                            
                            # Download all queries
                            all_queries = "\n\n".join([f"-- {q['name']}\n{q['query']}" for q in queries])
                            st.download_button(
                                "📥 Download All Splunk Queries",
                                all_queries,
                                f"splunk_queries_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                "text/plain"
                            )
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
                        st.info("💡 Check your API key in .env file")
            else:
                st.warning("⚠️ Please describe the incident")
    
    elif "Phishing" in analysis_type:
        st.markdown("### 📧 Email Analysis")
        email = st.text_area("Paste email:", placeholder="From: ...", height=200)
        
        if st.button("🔍 Analyze", type="primary", use_container_width=True):
            if email:
                with st.spinner("🤖 Analyzing..."):
                    prompt = f"Analyze for phishing:\n\nRISK SCORE (0-100):\nRED FLAGS:\nVERDICT:\nGUIDANCE:\n\nEMAIL:\n{email}"
                    try:
                        model = genai.GenerativeModel('gemini-2.5-flash')
                        response = model.generate_content(prompt)
                        st.markdown(response.text)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif "Log" in analysis_type:
        st.markdown("### 📊 Log Analysis")
        log_file = st.file_uploader("Upload log", type=['log', 'txt', 'csv'])
        
        if st.button("🔍 Analyze", type="primary", use_container_width=True):
            if log_file:
                with st.spinner("🤖 Analyzing..."):
                    logs = log_file.getvalue().decode('utf-8', errors='ignore')[:10000]
                    prompt = f"Analyze security logs:\n\nSUMMARY:\nFINDINGS:\nANOMALIES:\nQUERIES:\n\nLOGS:\n{logs}"
                    try:
                        model = genai.GenerativeModel('gemini-2.5-flash')
                        response = model.generate_content(prompt)
                        st.markdown(response.text)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

with col2:
    st.subheader("📊 Stats")
    st.metric("Analyses", len(st.session_state.history))
    
    if st.session_state.history:
        st.markdown("---")
        st.subheader("📜 Recent")
        for item in reversed(st.session_state.history[-3:]):
            with st.expander(f"{item['timestamp']}"):
                st.markdown(f"**{item.get('title', 'N/A')}**")

st.markdown("---")
st.markdown('<div style="text-align:center;color:#666;"><p>🛡️ SecureGPT - Gemini 2.5 Flash</p></div>', unsafe_allow_html=True)


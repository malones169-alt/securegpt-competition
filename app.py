import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import os
import json
import re
from datetime import datetime

# Load API key - Streamlit Cloud uses secrets, local uses .env
api_key = None

if "GOOGLE_API_KEY" in st.secrets:
    api_key = st.secrets["GOOGLE_API_KEY"]
else:
    load_dotenv()
    api_key = os.getenv('GOOGLE_API_KEY')

if not api_key:
    st.error("🚨 CRITICAL: No API key found! Add GOOGLE_API_KEY to Streamlit secrets.")
    st.stop()

genai.configure(api_key=api_key)

st.set_page_config(page_title="SecureGPT", page_icon="🛡️", layout="wide")
if api_key:
    genai.configure(api_key=api_key)
else:
    st.error("🚨 CRITICAL: No API key configured!")
st.set_page_config(page_title="SecureGPT", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main-header {
    font-size: 3.5rem; 
    font-weight: bold; 
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-align: center; 
    padding: 1rem;
}
.sub-header {
    font-size: 1.3rem; 
    color: #555; 
    text-align: center; 
    margin-bottom: 2rem;
}
.stButton>button {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-radius: 8px;
    font-weight: 600;
}
div[data-testid="stMetricValue"] {
    font-size: 2rem;
    color: #667eea;
}
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
                    "description": "User workstation DESKTOP-W10-045 infected with ransomware at 14:30 UTC. All files encrypted with .locked extension. Ransom note demands 5 Bitcoin within 48 hours. Network logs show initial connection to IP 185.220.101.45 on port 4444. Process tree shows powershell.exe spawning cmd.exe and vssadmin.exe. User Jane.Smith reported receiving phishing email 30 minutes prior.",
                    "severity": "Critical"
                },
                "PowerShell C2 Beacon": {
                    "description": "EDR alert on LAPTOP-SALES-012 for encoded PowerShell at 09:15 UTC. Base64 decoded command reveals download from malicious-domain.tk/payload.ps1. Process established persistent HTTPS connections to 203.0.113.42:443 every 60 seconds. Suspicious scheduled task 'WindowsUpdateCheck' created. Memory dump shows Cobalt Strike indicators.",
                    "severity": "High"
                },
                "Lateral Movement": {
                    "description": "Multiple failed auth attempts from account SERVICE_ADMIN across 15 workstations in 10 minutes. Successful logon to HR-FILE-SERVER using pass-the-hash. PsExec.exe executed remotely on three systems. Mimikatz indicators found. Admin share access from unusual IP 10.50.25.89.",
                    "severity": "Critical"
                
                },
                 "Phishing Campaign": {
                     "description": "Mass phishing campaign detected targeting finance department. 45 employees received emails from 'cfo@company-secure[.]com' with Excel attachment 'Q4_Bonuses.xlsm'. Macro executes PowerShell download cradle. 3 users clicked and enabled macros. Credential harvesting page detected at hxxps://portal-login-verify[.]xyz. MFA prevented full compromise on 2 accounts. One account (finance.user@company.com) successfully compromised from IP 198.18.0.50 (Russia).",
                     "severity": "High"
                },
                  "Insider Threat Data Exfil": {
                      "description": "Departing employee (termination scheduled in 2 days) accessed sensitive customer database outside normal hours (02:00-04:30 UTC). Downloaded 50GB of data to personal USB drive (SanDisk 64GB, SN: 4C530001). File activity shows copying customer_master.db, financial_records_2024.xlsx, and proprietary source code. Employee VPN'd from home IP, cleared browser history, and used company-issued laptop. HR flagged resignation as 'hostile departure' - employee moving to competitor.",
                      "severity": "Critical"
                 }
            }
            sample_choice = st.selectbox("Select sample:", [""] + list(sample_incidents.keys()))
            
            if sample_choice and st.button("📋 Load Sample", use_container_width=True):
                st.session_state.sample_title = sample_choice
                st.session_state.sample_description = sample_incidents[sample_choice]["description"]
                st.session_state.sample_severity = sample_incidents[sample_choice]["severity"]
                st.rerun()
        
        title = st.text_input("Incident Title", value=st.session_state.get('sample_title', ''), placeholder="e.g., Suspicious PowerShell")
        description = st.text_area("Describe the incident:", value=st.session_state.get('sample_description', ''), placeholder="Details...", height=150)
        files = st.file_uploader("Upload evidence (optional)", accept_multiple_files=True, type=['txt','log','png','jpg','csv'])
        severity_options = ["Unknown", "Low", "Medium", "High", "Critical"]
        severity = st.selectbox("Severity", severity_options, index=severity_options.index(st.session_state.get('sample_severity', 'Unknown')))
        
        if st.button("🔍 Analyze Incident", type="primary", use_container_width=True):
            if description:
                with st.spinner("🤖 Analyzing..."):
                    prompt = "You are a Senior SOC Analyst. Analyze this incident:\n\n"
                    prompt += f"Title: {title}\nSeverity: {severity}\nDescription: {description}\n\n"
                    prompt += "Provide: 1) Executive Summary 2) Assessment 3) MITRE ATT&CK 4) IOCs 5) Response Actions 6) Queries 7) Remediation 8) Timeline"
                    
                    try:
                        model = genai.GenerativeModel('gemini-2.5-flash')
                        content = [prompt]
                        st.info(f"🔑 API Key loaded: {api_key[:20]}...")  # Show first 20 chars for debugging
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
                            
                            st.download_button("📥 Download IOCs (CSV)", ioc_csv, f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
                        
                        # SPLUNK QUERIES
                        st.markdown("---")
                        st.subheader("🔎 Splunk Investigation Queries")
                        
                        with st.expander("📊 View Generated Splunk Queries", expanded=True):
                            queries = []
                            
                            if iocs['ips']:
                                ip_list = " OR ".join([f'dest_ip="{ip}"' for ip in iocs['ips']])
                                queries.append({'name': 'Search for Suspicious IPs', 'query': f'index=* ({ip_list})\n| stats count by src_ip, dest_ip, dest_port\n| sort -count'})
                            
                            if 'powershell' in description.lower() or 'powershell' in response.text.lower():
                                queries.append({'name': 'PowerShell Execution Events', 'query': 'index=windows EventCode=4688 process_name=*powershell.exe\n| table _time, Computer, User, CommandLine\n| sort -_time'})
                                queries.append({'name': 'Encoded PowerShell Commands', 'query': 'index=windows powershell (encodedcommand OR -enc OR -e)\n| table _time, Computer, User, CommandLine\n| sort -_time'})
                            
                            if iocs['ips']:
                                for ip in iocs['ips'][:3]:
                                    queries.append({'name': f'Connections to {ip}', 'query': f'index=firewall OR index=proxy dest_ip="{ip}"\n| stats count by src_ip, dest_port\n| sort -count'})
                            
                            if 'ransomware' in description.lower() or 'encrypted' in description.lower():
                                queries.append({'name': 'File Modification Activity', 'query': 'index=windows EventCode=4663 Object_Type=File\n| stats count by Computer, Object_Name, Process_Name\n| where count > 100'})
                            
                            queries.append({'name': 'Process Timeline', 'query': 'index=windows EventCode=4688\n| table _time, Computer, Process_Name, Process_Command_Line\n| sort _time'})
                            
                            for i, q in enumerate(queries, 1):
                                st.markdown(f"**{i}. {q['name']}**")
                                st.code(q['query'], language='spl')
                            
                            all_queries = "\n\n".join([f"-- {q['name']}\n{q['query']}" for q in queries])
                            st.download_button("📥 Download All Queries", all_queries, f"splunk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                        
                        result = {'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'title': title, 'analysis': response.text}
                        st.session_state.history.append(result)
                        
                        st.markdown("---")
                        col_e1, col_e2 = st.columns(2)
                        with col_e1:
                            st.download_button("📄 Download TXT", response.text, f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                        with col_e2:
                            st.download_button("📊 Download JSON", json.dumps(result, indent=2), f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                    
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
            else:
                st.warning("⚠️ Please describe the incident")
    
    elif "Phishing" in analysis_type:
        st.markdown("### 📧 Email Analysis")
        email = st.text_area("Paste email:", placeholder="From: ...", height=200)
        
        if st.button("🔍 Analyze", type="primary", use_container_width=True):
            if email:
                with st.spinner("🤖 Analyzing..."):
                    try:
                        model = genai.GenerativeModel('gemini-2.5-flash')
                        response = model.generate_content(f"Analyze for phishing:\n\nRISK SCORE:\nRED FLAGS:\nVERDICT:\n\nEMAIL:\n{email}")
                        st.markdown(response.text)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif "Log" in analysis_type:
        st.markdown("### 📊 Log Analysis")
        log_file = st.file_uploader("Upload log", type=['log', 'txt', 'csv'])
        
        if st.button("🔍 Analyze", type="primary", use_container_width=True):
            if log_file:
                with st.spinner("🤖 Analyzing..."):
                    try:
                        model = genai.GenerativeModel('gemini-2.5-flash')
                        logs = log_file.getvalue().decode('utf-8', errors='ignore')[:10000]
                        response = model.generate_content(f"Analyze security logs:\n\nSUMMARY:\nFINDINGS:\n\nLOGS:\n{logs}")
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









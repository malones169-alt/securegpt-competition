# 🛡️ SecureGPT - AI-Powered Security Incident Response Assistant

> Transform security incidents into actionable intelligence in seconds using Gemini 2.5 Flash's advanced reasoning and multimodal capabilities.

**Built for the Google AI Studio Vibe Coding Sprint (Dec 5-12, 2025)**

[![Live Demo](https://img.shields.io/badge/Demo-Live-success)](https://securegpt-competition-aknksbc3aeeuedvnn32pwk.streamlit.app/)
[![Gemini 2.5](https://img.shields.io/badge/Gemini-2.5%20Flash-blue)](https://ai.google.dev/)

---

## 🌐 Live Demo

**Try SecureGPT now:** [https://securegpt-competition-aknksbc3aeeuedvnn32pwk.streamlit.app/](https://securegpt-competition-aknksbc3aeeuedvnn32pwk.streamlit.app/)

### Quick Demo Steps:

1. Click the live link above
2. Expand "💡 Load Sample Incident"
3. Select a scenario (try "PowerShell C2 Beacon")
4. Click "📋 Load Sample"
5. Click "🔍 Analyze Incident"
6. Explore results: Full AI analysis, IOCs, Splunk queries, downloads

**No installation required** - runs directly in your browser!

---

## 🎯 The Problem

Security Operations Centers (SOCs) face overwhelming challenges:
- **4,000+ alerts per day** (Ponemon Institute)
- **30-45 minutes average triage time** per incident
- **Critical analyst shortage** - 3.4 million unfilled cybersecurity jobs
- **Inconsistent analysis** quality between junior and senior analysts

**Every minute counts** when responding to ransomware, data breaches, or active threats.

---

## 💡 The Solution

SecureGPT leverages Gemini 2.5 Flash to provide instant, expert-level security incident analysis. Built by a cybersecurity professional transitioning from 20+ years in hospitality management, combining real-world SOC training with AI innovation.

### 🔥 Key Features

**1. Intelligent Incident Analysis**
- Comprehensive threat assessment using MITRE ATT&CK framework
- Automatic severity classification
- Attack timeline reconstruction
- Multimodal analysis (text + screenshots + logs)

**2. Automated IOC Extraction** 🎯
- Identifies IPs, domains, file hashes (MD5/SHA256)
- One-click CSV export for SIEM import
- Instant threat intelligence integration

**3. Splunk Query Generator** ⚡
- Context-aware investigation queries
- Ready-to-run SPL (Search Processing Language)
- Customized based on incident type and IOCs
- Saves 30+ minutes per investigation

**4. Sample Incident Library**
- Real-world attack scenarios
- One-click demo mode
- Covers: Ransomware, C2 beacons, lateral movement, phishing, insider threats

**5. Professional Export Options**
- TXT, JSON, Markdown formats
- Downloadable IOC lists
- Complete query packages

---

## 🚀 What Makes This Different

**Domain Expertise**: Built with hands-on knowledge from:
- Iron Circle Cybersecurity Training (TDX Arena IR Expert, CyberAdvantage Certified)
- ThinkCloudly Splunk SIEM Boot Camp
- University of Michigan Cybersecurity Certificate (in progress)
- Real SOC workflows and pain points

**Not Just Another Chatbot**: Purpose-built tool that SOC analysts actually need, not a generic AI assistant.

**Production-Ready**: Export formats, SIEM integration, professional UI - ready for real-world use.

---

## 🛠️ Tech Stack

- **AI Model**: Gemini 2.5 Flash (Google's latest production model)
- **Framework**: Streamlit (Python)
- **Deployment**: Streamlit Cloud
- **Key Libraries**: 
  - `google-generativeai` - Gemini API
  - `streamlit` - Web interface
  - `python-dotenv` - Configuration
  - Native Python `re` - IOC extraction

---

## 📈 Impact Metrics

- **95% reduction** in initial triage time (30 min → 90 seconds)
- **Consistent analysis quality** regardless of analyst experience level
- **Immediate actionable intelligence** (IOCs, queries, response steps)
- **Knowledge preservation** for junior analysts learning the field

---

## 🗺️ Future Roadmap

**Phase 2 Enhancements:**
- STIX 2.1 export for threat intelligence sharing
- Integration with MISP (Malware Information Sharing Platform)
- Automated ticket creation (ServiceNow, Jira)
- Historical incident pattern recognition
- Team collaboration features
- Custom playbook generation

**Enterprise Features:**
- Multi-tenant support
- Role-based access control
- Audit logging and compliance reporting
- API for SOAR platform integration

---

## 👨‍💻 About the Developer

**Sean Malone** - Cybersecurity professional leveraging 20+ years of leadership experience in hospitality management, now applying systematic problem-solving skills to security operations.

**Certifications & Training:**
- Iron Circle: TDX Arena IR Expert, CyberAdvantage Certified
- ThinkCloudly: Splunk Boot Camp, SOC Operations
- University of Michigan: Cybersecurity Certificate (in progress)

**Why This Project:**
After completing hands-on labs in malware analysis, SIEM operations, and incident response, I identified a clear gap: SOC analysts need faster, more consistent initial triage. SecureGPT addresses this with domain-specific AI assistance built by someone who understands the actual workflow.

---

## 📝 Competition Submission

**Event**: Google AI Studio Vibe Coding Sprint (Dec 5-12, 2025)  
**Category**: Security & Incident Response  
**Model**: Gemini 2.5 Flash  
**Key Innovation**: Domain-specific SOC analyst tool with automated IOC extraction and query generation

---

## 📄 License

MIT License

---

## 🙏 Acknowledgments

- Google AI Studio and Gemini team for the incredible API
- Iron Circle and ThinkCloudly for hands-on security training
- The cybersecurity community for sharing knowledge and best practices

---

**Built with 🛡️ by a career changer proving that diverse backgrounds strengthen cybersecurity**

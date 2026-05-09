# 🛡️ MailShield

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![Google Apps Script](https://img.shields.io/badge/Gmail-Add--on-orange)
![Security](https://img.shields.io/badge/Security-Phishing_Detection-red)

Real-time Gmail phishing detection add-on built with Google Apps Script and FastAPI.

MailShield analyzes suspicious emails directly inside Gmail, detects phishing indicators, generates explainable threat scores, and allows users to instantly quarantine malicious emails.

<img width="259" height="825" alt="image" src="https://github.com/user-attachments/assets/998b97f6-1839-461e-9666-b6646f8b9659" />



# Table of Contents

- [What is MailShield](#-what-is-mailshield)
- [Features](#-features)
- [Architecture](#architecture)
- [Threat Analysis Engine](#threat-analysis-engine)
- [Risk Scoring System](#risk-scoring-system)
- [Security Design Decisions](#security-design-decisions)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [How to Run](#️-how-to-run)
- [Local Setup](#local-setup)
- [Future Improvements](#future-improvements)
- [Screenshots](#screenshots)


## 📌 What is MailShield?

MailShield is a Gmail phishing detection add-on that helps users identify suspicious emails directly inside their inbox.

The add-on analyzes the opened email, extracts key signals such as the sender, subject, body content, links, and attachments, and sends them to a FastAPI backend for risk analysis.

The backend evaluates phishing indicators, generates an explainable threat score, and returns a clear verdict:

- 🟢 SAFE
- 🟡 SUSPICIOUS
- 🔴 MALICIOUS

MailShield also allows users to take immediate action by moving suspicious or malicious emails to spam directly from the add-on.


## ✨ Features

### 🔍 Real-Time Email Analysis
Analyzes emails directly inside Gmail in real time using a Gmail Add-on interface.

### 🚨 Phishing Detection Engine
Detects suspicious phishing indicators such as:
- urgency or fear-based language
- suspicious sender domains
- URL shorteners
- risky attachments
- phishing-related scenarios
- brand impersonation attempts

### 🌐 URL Reputation Analysis
Performs URL reputation and risk checks on extracted links, including:
- suspicious TLD detection
- excessive subdomains
- shortened URLs
- deceptive URL patterns
- IP-based links

### 📊 Explainable Threat Scoring
Generates transparent risk scores based on detected phishing signals and explains why an email was flagged.

### 🟢 Risk-Based Verdicts
Categorizes emails into:
- SAFE
- SUSPICIOUS
- MALICIOUS

### 🛡️ Spam Remediation
Allows users to instantly move suspicious emails to Gmail spam directly from the add-on.

### ⚡ FastAPI Backend
Uses a modular Python FastAPI backend for scalable phishing analysis and threat processing.

### 🔐 Security-Focused Design
Designed with security considerations such as:
- avoiding direct URL fetching to reduce SSRF risk
- strict separation between frontend and backend
- explainable security heuristics


## Architecture

MailShield is built using a modular client-server architecture composed of two main components:

1. Gmail Add-on frontend (Google Apps Script)
2. FastAPI backend threat analysis engine

The Gmail add-on is responsible for:
- interacting with the user directly inside Gmail
- extracting email metadata and content
- sending analysis requests to the backend
- displaying explainable threat analysis results
- triggering remediation actions such as moving emails to spam

The FastAPI backend is responsible for:
- phishing signal detection
- URL reputation analysis
- risk score calculation
- verdict generation
- explainable threat scoring

### 🔄 Analysis Flow

```text
User opens email in Gmail
        ↓
MailShield Gmail Add-on
        ↓
Extracts:
- sender
- subject
- body
- links
- attachments
        ↓
JSON request sent to FastAPI backend
        ↓
Threat Analysis Engine
    ├── phishing heuristics
    ├── URL reputation analysis
    ├── sender validation
    ├── attachment checks
        ↓
Risk score + verdict generated
        ↓
Results returned to Gmail Add-on
        ↓
User can:
- review threat signals
- view security recommendations
- move email to spam

```

## Threat Analysis Engine

MailShield analyzes suspicious emails using a heuristic-based phishing detection system implemented in the FastAPI backend.

The analysis process evaluates multiple phishing-related indicators extracted from the email content, sender information, links, and attachments.

### Analyzed Signals

The backend currently checks for indicators such as:

- suspicious sender domains
- brand impersonation attempts
- urgency or fear-based language
- requests for sensitive information
- suspicious or deceptive URLs
- shortened links
- suspicious TLDs
- risky attachment types
- excessive link volume
- phishing-related scenarios
- aggressive formatting patterns
- generic greetings

### URL Reputation Checks

The URL analysis logic evaluates extracted links for phishing-related indicators, including:

- suspicious top-level domains (TLDs)
- excessive subdomains
- shortened URLs
- deceptive URL structures
- IP-based URLs
- suspicious phishing keywords inside URLs

The system intentionally avoids directly fetching URLs in order to reduce SSRF-related risks and maintain strict trust boundaries.

### Explainable Threat Detection

Instead of returning only a numeric score, MailShield provides explainable analysis results.

Each flagged email includes:
- detected phishing signals
- human-readable explanations
- risk-based verdicts
- actionable recommendations

### Verdict Generation

After evaluating all phishing indicators, the backend generates:
- a numerical risk score (0–100)
- a final verdict:
  - SAFE
  - SUSPICIOUS
  - MALICIOUS

The results are returned to the Gmail add-on and displayed directly inside the Gmail interface.

## Risk Scoring System

MailShield uses a heuristic-based risk scoring system to estimate the likelihood that an email is malicious or phishing-related.

Each detected phishing indicator contributes a weighted number of points to the final risk score.

The final score is normalized to a range of 0–100 and mapped into one of three verdict categories.

### Verdict Thresholds

| Score Range | Verdict |
|---|---|
| 0–30 | 🟢 SAFE |
| 31–65 | 🟡 SUSPICIOUS |
| 66–100 | 🔴 MALICIOUS |

### Example Risk Signals

| Signal | Score Impact |
|---|---|
| Suspicious sender domain | +20 |
| Brand impersonation attempt | +20 |
| Urgency or fear-based language | +15 |
| Sensitive information request | +20 |
| URL shortener detected | +15 |
| Suspicious TLD | +15 |
| Excessive link volume | +10 |
| Risky attachment type | +25 |
| Generic greeting | +10 |
| Aggressive formatting | +10 |

### Explainable Scoring

Instead of returning only a numeric value, MailShield also explains which phishing indicators contributed to the final score.

Example:

```text
🔗 URL shortener detected
⏰ Urgency language detected
🎣 Delivery-related phishing scenario

```

## Security Design Decisions

MailShield was designed with a security-focused architecture and several defensive design decisions.

### No Direct URL Fetching

MailShield intentionally avoids directly opening or fetching extracted URLs.

This prevents potential SSRF (Server-Side Request Forgery) risks and avoids interacting with malicious infrastructure during analysis.

Instead, URLs are analyzed statically using heuristic-based reputation checks.

### Frontend / Backend Separation

The Gmail add-on frontend and the phishing analysis backend are fully separated.

The Gmail Add-on is responsible only for:
- user interaction
- email extraction
- displaying analysis results

All threat analysis logic is handled by the FastAPI backend.

This separation improves:
- maintainability
- scalability
- security isolation

### Explainable Detection

MailShield avoids opaque "black-box" scoring systems.

Every verdict includes:
- detected phishing indicators
- human-readable explanations
- actionable recommendations

This improves transparency and helps users understand why an email was flagged.

### Principle of Minimal Actions

The system does not automatically delete emails or perform destructive actions.

Instead, users remain in control and can choose actions such as:
- reviewing the analysis
- moving the email to spam
- ignoring low-risk alerts

### Modular Threat Analysis

The backend was designed to support future security integrations, such as:
- VirusTotal
- Google Safe Browsing
- domain age analysis
- AI-generated phishing explanations
- SOC alerting workflows

without requiring major architectural changes.

## 🧰 Tech Stack

### 🎨 Frontend
- Google Apps Script
- Gmail Add-ons API
- CardService UI

### ⚙️ Backend
- Python 3
- FastAPI
- Pydantic
- Uvicorn

### 🛡️ Security & Analysis
- Heuristic-based phishing detection
- URL reputation analysis
- Risk scoring engine
- Explainable threat analysis

### 🛠️ Development & Tooling
- Git & GitHub
- ngrok
- REST APIs
- OAuth scopes

## 📁 Project Structure

```text
MailShield/
│
├── backend/
│   ├── app/
│   │   ├── analyser.py
│   │   ├── url_reputation.py
│   │   ├── models.py
│   │   └── main.py
│   │
│   └── requirements.txt
│
├── gmail-addon/
│   ├── Code.gs
│   └── appsscript.json
│
├── adding_logo.png
├── README.md
└── .gitignore
```

### Structure Overview

| File | Description |
|---|---|
| `analyser.py` | Main phishing detection and scoring logic |
| `url_reputation.py` | URL reputation and phishing-related URL checks |
| `models.py` | FastAPI request/response models using Pydantic |
| `main.py` | FastAPI application entry point |
| `Code.gs` | Gmail Add-on frontend implementation |
| `appsscript.json` | Gmail Add-on manifest and OAuth scopes configuration |

## ▶️ How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/orshalem/MailShield.git
cd MailShield
```

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Backend Dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Start the FastAPI Backend

```bash
uvicorn app.main:app --reload --port 8080
```

The backend will run on:

```text
http://127.0.0.1:8080
```

### 5. Expose the Backend Using ngrok

```bash
ngrok http 8080
```

Copy the generated HTTPS forwarding URL.

Example:

```text
https://your-ngrok-url.ngrok-free.app
```

### 6. Configure the Gmail Add-on

Open the Google Apps Script project and update the backend URL inside:

```text
Code.gs
```

Replace the existing API endpoint with your ngrok URL.

### 7. Deploy the Gmail Add-on

Inside Google Apps Script:

- Deploy → Test deployments
- Install the Gmail Add-on
- Approve OAuth permissions
- Open Gmail and test MailShield

## Local Setup

### Backend Environment Variables

Create a `.env` file inside the `backend/` directory if additional configuration is required.

Example:

```env
API_HOST=127.0.0.1
API_PORT=8080
```

### Gmail Add-on Configuration

Inside the Google Apps Script project:

- configure the backend API endpoint
- update the ngrok forwarding URL when running locally
- configure OAuth scopes inside `appsscript.json`

Required scopes include:

```json
"https://www.googleapis.com/auth/gmail.addons.execute",
"https://mail.google.com/",
"https://www.googleapis.com/auth/script.external_request"
```

### Recommended Local Development Flow

1. Start the FastAPI backend
2. Start ngrok
3. Update the backend URL in `Code.gs`
4. Refresh the Gmail Add-on
5. Open Gmail and analyze emails

### Development Notes

- The backend uses FastAPI with automatic reload enabled during development.
- ngrok is required because Gmail Add-ons cannot access localhost directly.
- The phishing detection logic is fully implemented in the Python backend.
- The Gmail Add-on is responsible only for UI rendering and Gmail interaction.
  
## Future Improvements

### 🌐 VirusTotal / Google Safe Browsing Integration
Integrate external threat intelligence APIs to check whether extracted URLs were previously reported as malicious or phishing-related.

### 🧠 AI-Based Threat Explanations
Use LLM-based analysis to generate human-readable explanations describing why an email may be suspicious.

Example:

```text
This email creates artificial urgency and attempts to pressure the user into clicking suspicious links.
```

### 🚨 Slack / SOC Alerting
Automatically send alerts for high-risk emails to Slack or SOC workflows for faster incident response and monitoring.

## Screenshots

| Gmail Integration | Initial Analysis Screen |
|---|---|
| <img src="https://github.com/user-attachments/assets/965b5065-ee29-46c2-a0ab-22d6cb4c9f45" width="260"/> | <img src="https://github.com/user-attachments/assets/1d98246b-73ec-43cc-a8e6-8ae8a31e38a7" width="260"/> |

| Threat Analysis Result |
|---|
| <img src="https://github.com/user-attachments/assets/f327eee2-24e2-4337-83b9-94ec9c80b8c7" width="300"/> |


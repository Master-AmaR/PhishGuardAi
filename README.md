# PhishGuard Triage

PhishGuard Triage is a Flask-based phishing triage and evidence platform for URL analysis, suspicious email inspection, VirusTotal reputation enrichment, and SOC-style detection logging.

## Features

- Evidence-focused SOC dashboard
- URL scanner with local feature extraction and VirusTotal proof links
- Email phishing triage with explainable reasons, URL extraction, and reputation checks
- SQLite-backed scan history, detection logs, and report data model
- REST API architecture for scan automation
- VirusTotal API integration service using environment variables
- PDF-ready report view through browser print/export workflow
- Bootstrap 5, Bootstrap Icons, Chart.js, responsive sidebar, glassmorphism panels, and cybersecurity grid styling

## Project Structure

```text
PhishGuard Triage/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── database/
│   ├── db.py
│   └── schema.sql
├── models/
│   └── repositories.py
├── routes/
│   ├── api.py
│   └── dashboard.py
├── services/
│   ├── ml_service.py
│   └── virustotal_service.py
├── templates/
├── static/
│   ├── css/
│   ├── js/
│   └── img/
├── ml_models/
├── utils/
├── uploads/
└── logs/
```

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY="replace-with-a-secure-key"
$env:VIRUSTOTAL_API_KEY="optional-virustotal-api-key"
python app.py
```

Open `http://127.0.0.1:5000`.

## REST API

### URL Scan

```http
POST /api/scan/url
Content-Type: application/json

{"url": "http://secure-update-verify-alert.com"}
```

### Email Scan

```http
POST /api/scan/email
Content-Type: multipart/form-data

content=Raw email body or upload email_file=.eml
```

### Threat Intelligence Lookup

```http
POST /api/intel/reputation
Content-Type: application/json

{"target": "secure-login.example.com"}
```

## ML Integration Notes

`services/ml_service.py` currently contains production-shaped placeholder logic for feature extraction and classification. Replace `predict_url` and `analyze_email_content` internals with model inference when trained models are available. The intended loading path is configured by `ML_MODEL_PATH` and the `ml_models/` directory.

## VirusTotal

Set `VIRUSTOTAL_API_KEY` in the environment. If no key is configured, the app remains usable and returns a safe standby response for VirusTotal cards and API calls.

## Security Notes

- Secrets are read from environment variables.
- Upload extensions are restricted to `.eml` and `.txt`.
- File names are sanitized through Werkzeug.
- The structure is ready for Flask-WTF CSRF protection if form-based session hardening is added.

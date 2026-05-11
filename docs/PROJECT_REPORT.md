# PhishGuard AI: Web and Email Phishing Detection System

## 1. Project Overview

PhishGuard AI is a phishing detection and triage platform built to identify suspicious websites and suspicious email content. The project combines a Flask-based web application, a SQLite evidence database, rule-based and machine-learning-ready analysis logic, VirusTotal reputation enrichment, and a Chrome extension that works on normal websites and Gmail.

The system is designed for cybersecurity awareness, SOC-style triage, and phishing investigation. It allows a user to scan URLs, analyze raw email content, inspect extracted indicators, view threat logs, and receive browser warnings through a Chrome extension.

## 2. Problem Statement

Phishing attacks are one of the most common cybersecurity threats. Attackers often use fake login pages, urgent messages, suspicious links, impersonation, and social engineering to steal credentials or sensitive information.

Traditional users may not notice signs such as:

- HTTP links instead of HTTPS.
- Suspicious keywords such as verify, login, password, account, or urgent.
- Deep subdomains and misleading URL structures.
- Untrusted domains inside official-looking emails.
- Email messages asking for immediate action.
- URLs that require reputation checking through external intelligence sources.

The aim of this project is to provide an easy-to-use phishing detection system that helps users identify risky websites and emails before interacting with them.

## 3. Objectives

The main objectives of PhishGuard AI are:

- Detect suspicious URLs using local feature extraction and scoring.
- Analyze email text for phishing indicators.
- Extract URLs from email content and check their reputation.
- Enrich results using VirusTotal when an API key is available.
- Store scan history and detection logs in a database.
- Provide a cybersecurity dashboard for monitoring threats.
- Offer a Chrome extension for real-time website and Gmail scanning.
- Explain scan results using human-readable reasons.

## 4. Technologies Used

### Backend

- Python: Main backend programming language.
- Flask: Web framework used to build routes, pages, and APIs.
- SQLite: Local database for scan history and logs.
- Werkzeug: Used for secure uploaded filename handling.
- python-dotenv: Loads environment variables from `.env`.
- requests: Used for VirusTotal API calls.

### Machine Learning and Analysis

- scikit-learn: Used for model training/inference support.
- joblib: Used to load the trained URL model from `ml_models/url_model.joblib`.
- Custom heuristic rules: Used for URL and email phishing scoring.

### Frontend

- HTML/Jinja templates: Flask server-rendered pages.
- CSS: Custom cybersecurity-themed interface.
- Bootstrap 5: Responsive layout and UI components.
- Bootstrap Icons: Icons used in navigation and interface.
- Chart.js: Threat timeline chart on the dashboard.
- JavaScript Fetch API: Sends scan requests to backend APIs.

### Browser Extension

- Chrome Extension Manifest V3.
- JavaScript service worker background script.
- Content scripts for webpages and Gmail.
- Popup UI for active tab scanning.
- Chrome extension APIs: `tabs`, `storage`, `runtime`, and `action`.

### Threat Intelligence

- VirusTotal API integration.
- Offline fallback when VirusTotal API key is not configured.

## 5. System Architecture

PhishGuard AI has two major parts:

1. Flask Web Application
2. Chrome Extension

The Flask application acts as the core analysis engine and dashboard. It exposes web pages and REST API endpoints. The Chrome extension communicates with this backend to scan active websites and Gmail messages.

### High-Level Flow

1. User enters a URL in the dashboard or opens a website in Chrome.
2. The system extracts URL features.
3. The URL is scored using heuristic rules and, when available, a trained model.
4. VirusTotal reputation is checked if configured.
5. A verdict is generated: Benign, Potentially Suspicious, Suspicious Phishing, or Credential Harvesting Phishing.
6. The result is stored in SQLite.
7. Dashboard metrics and logs are updated.
8. The Chrome extension displays warnings or safe results to the user.

For Gmail:

1. User opens an email in Gmail.
2. The Gmail content script extracts visible sender, subject, and body text.
3. The extension sends the email content to the Flask backend.
4. Backend analyzes suspicious language, URLs, domains, headers, and reputation.
5. The verdict is shown directly inside Gmail using a floating result panel.

## 6. Project Structure

```text
TTL-project/
|-- app.py
|-- config.py
|-- requirements.txt
|-- README.md
|-- database/
|   |-- db.py
|   |-- schema.sql
|-- models/
|   |-- repositories.py
|-- routes/
|   |-- api.py
|   |-- dashboard.py
|-- services/
|   |-- ml_service.py
|   |-- virustotal_service.py
|-- templates/
|   |-- base.html
|   |-- dashboard.html
|   |-- url_scanner.html
|   |-- email_analyzer.html
|   |-- logs.html
|   |-- reports.html
|-- static/
|   |-- css/style.css
|   |-- js/app.js
|-- ml_models/
|   |-- url_model.joblib
|-- scripts/
|   |-- train_url_model.py
|-- uploads/
|-- logs/
|-- phishguard-chrome-extension/
|   |-- manifest.json
|   |-- background.js
|   |-- content.js
|   |-- gmail_content.js
|   |-- popup.html
|   |-- popup.css
|   |-- popup.js
```

## 7. Backend Design

### app.py

`app.py` creates and configures the Flask application. It loads settings from `config.py`, initializes the database, registers the dashboard routes, and registers API routes under `/api`.

Main responsibilities:

- Create Flask app.
- Load configuration.
- Initialize SQLite database.
- Register route blueprints.
- Start server on `127.0.0.1:5000`.

### config.py

`config.py` stores application configuration:

- `SECRET_KEY`
- SQLite database path
- VirusTotal API key
- Upload folder
- Maximum upload size
- Allowed email extensions
- ML model path
- Log file path

Environment variables are loaded from `.env`.

### routes/dashboard.py

This file handles normal web pages:

- Dashboard
- URL Scanner
- Email Analyzer
- Detection Logs
- Reports

These routes render templates and pass data from the database to the frontend.

### routes/api.py

This file provides REST API endpoints:

- `GET /api/metrics`: Returns dashboard metrics.
- `GET /api/timeline`: Returns threat timeline data.
- `GET /api/logs/recent`: Returns recent detection logs.
- `POST /api/scan/url`: Scans a URL.
- `POST /api/scan/email`: Scans email content or uploaded `.eml/.txt` file.
- `POST /api/intel/reputation`: Used by the Chrome extension for active tab reputation scanning.

## 8. Database Design

The project uses SQLite with the schema in `database/schema.sql`.

### url_scans

Stores URL scan results.

Important fields:

- `target_url`
- `classification`
- `threat_score`
- `ml_confidence`
- `vt_detection_ratio`
- `features_json`
- `created_at`

### email_scans

Stores email analysis results.

Important fields:

- `sender`
- `subject`
- `extracted_urls`
- `classification`
- `threat_score`
- `ml_confidence`
- `suspicious_terms`
- `created_at`

### detection_logs

Stores unified logs for URL and email detections.

Important fields:

- `target_source`
- `severity`
- `threat_type`
- `ai_confidence`
- `scan_source`
- `action_taken`
- `created_at`

### threat_reports

Reserved for report-style threat summaries.

Important fields:

- `title`
- `summary`
- `severity`
- `source`
- `created_at`

## 9. URL Detection Methodology

URL analysis is implemented mainly in `services/ml_service.py`.

The system extracts URL features such as:

- URL length
- HTTPS availability
- Suspicious characters
- Query parameter count
- Tracking parameter count
- Redirect markers
- IP-based host detection
- Domain name
- Subdomain depth
- Keyword hits
- Trusted shopping domain detection
- Known marketplace URL patterns

The system assigns a threat score based on these features. Examples:

- Missing HTTPS increases risk.
- IP-based URLs increase risk.
- Suspicious characters increase risk.
- Multiple redirect parameters increase risk.
- Phishing keywords increase risk.
- Deep subdomains increase risk.

The final classification is based on score ranges:

- 0-34: Benign / Low
- 35-54: Potentially Suspicious / Medium
- 55-79: Suspicious Phishing / High
- 80-99: Credential Harvesting Phishing / Critical

The app also supports loading a trained ML model from `ml_models/url_model.joblib` using `joblib`.

## 10. Email Detection Methodology

Email analysis is also implemented in `services/ml_service.py`.

The email scanner parses the message using Python's email parser and extracts:

- Sender
- Subject
- Reply-To
- Authentication results
- Microsoft spam headers, when available
- Sender IP, when available
- Plain text body
- Embedded URLs
- Evidence domains
- Suspicious terms
- URL shorteners

The email scanner looks for phishing indicators such as:

- Suspicious keywords: account, verify, urgent, password, suspended, restricted, login, update.
- Embedded URLs.
- Multiple unique domains.
- URL shorteners.
- Reply-To mismatch.
- SPF, DKIM, or DMARC failures.
- Weak authentication results.
- Elevated spam confidence level.
- Brand impersonation with unrelated domains.

The output includes:

- Classification
- Threat score
- ML confidence
- Severity
- Action
- Reasons explaining the verdict
- Extracted URLs
- URL reputation results

## 11. VirusTotal Integration

`services/virustotal_service.py` integrates with VirusTotal API v3.

The service can:

- Normalize URLs.
- Submit URLs to VirusTotal.
- Fetch reputation reports.
- Parse malicious, suspicious, harmless, and undetected counts.
- Generate a VirusTotal GUI report link.

If `VIRUSTOTAL_API_KEY` is not configured, the service returns an offline fallback response. This allows the project to keep working even without an API key.

## 12. Dashboard Features

The dashboard provides a SOC-style interface for phishing triage.

Main dashboard features:

- Total scan count.
- Phishing detection count.
- Active threat count.
- Average confidence metric.
- Threat timeline chart using Chart.js.
- Recent detection logs.
- Sidebar navigation.

The UI is built with:

- Flask templates.
- Bootstrap.
- Bootstrap Icons.
- Custom CSS.
- JavaScript dynamic updates.

## 13. URL Scanner Page

The URL scanner page allows users to manually enter a URL and analyze it.

It displays:

- Verdict.
- Threat score.
- ML confidence.
- URL features.
- VirusTotal detection ratio.
- VirusTotal proof link, when available.
- Extracted indicators.
- Recommended action.

## 14. Email Analyzer Page

The email analyzer page allows:

- Pasting raw email content.
- Uploading `.eml` or `.txt` files.
- Extracting URLs from email text.
- Showing suspicious language.
- Displaying sender and subject metadata.
- Showing URL reputation evidence.

This page is useful for investigating suspicious emails outside Gmail.

## 15. Detection Logs and Reports

The logs page shows detection history from the database. It supports filtering and searching through JavaScript.

The reports page provides a report-ready interface where scan history and metrics can be reviewed for documentation or presentation.

## 16. Chrome Extension Design

The Chrome extension is stored in `phishguard-chrome-extension/`.

### manifest.json

The extension uses Manifest V3.

Main permissions:

- `storage`: Save settings and cached verdicts.
- `tabs`: Read active tab information.
- Host permissions for all URLs, Gmail, and local Flask backend.

Main scripts:

- `background.js`
- `content.js`
- `gmail_content.js`
- `popup.js`

### background.js

The background script acts as the extension's service worker.

Responsibilities:

- Scan active tab URLs.
- Call the Flask backend reputation endpoint.
- Use local heuristic fallback when backend is unavailable.
- Cache verdicts.
- Set browser action badge warnings.
- Handle Gmail email scan messages.

### content.js

This script runs on normal websites. It receives verdicts from the background worker and can display warning UI on suspicious pages.

### popup.html, popup.css, popup.js

These files create the extension popup visible when clicking the extension icon.

Popup features:

- Shows active page verdict.
- Displays score and reasons.
- Allows user to manually scan the active tab.

### gmail_content.js

This script runs specifically on Gmail.

Responsibilities:

- Inject a floating "Scan with PhishGuard" button.
- Detect visible email body.
- Extract sender, subject, and body text.
- Send the email content to the background script.
- Display scan result inside Gmail.

The latest improvement makes the floating Gmail button visible on Gmail and shows a helpful message if no email is open.

## 17. API Endpoints

### POST /api/scan/url

Input:

```json
{
  "url": "http://secure-update-login.example.com"
}
```

Output includes:

- Classification
- Threat score
- Confidence
- Severity
- Action
- Extracted features
- VirusTotal result

### POST /api/scan/email

Input can be:

- Form field `content`
- Uploaded file `email_file`

Output includes:

- Sender
- Subject
- Extracted URLs
- Suspicious terms
- Reasons
- Severity
- Classification
- URL reputation

### POST /api/intel/reputation

Used by the Chrome extension.

Input:

```json
{
  "target": "https://example.com"
}
```

Output:

- Heuristic result
- VirusTotal result

## 18. Security Measures

The project includes several safety practices:

- Secrets are loaded from environment variables.
- File uploads are restricted to `.eml` and `.txt`.
- Uploaded filenames are sanitized with `secure_filename`.
- Maximum content length is configured.
- HTML output is escaped on the frontend.
- Chrome extension does not expose backend details to normal users.
- VirusTotal errors are handled gracefully.
- Local fallback logic keeps scanning available when backend enrichment fails.

## 19. Recent Fixes and Improvements

During testing, the Gmail floating button was not visible on the inbox page. This happened because the script only displayed the button when an email body was already open.

Fix applied:

- The Gmail floating button now appears on Gmail.
- If no email is selected, it tells the user to open an email first.

A second issue showed "Looks safe: Scan unavailable", which was misleading.

Fix applied:

- Scan failures now show "Scan unavailable" as an unknown/warning state.
- Email scan timeout was increased to handle slow backend or VirusTotal checks.
- Real error messages are returned from the background script.

## 20. Testing Performed

Testing included:

- Checking Flask backend metrics endpoint.
- Testing `/api/scan/email` through PowerShell.
- Testing Gmail floating button injection.
- Testing Chrome popup active page scanning.
- Running JavaScript syntax checks with `node --check`.

Example verified backend endpoint:

```text
GET http://127.0.0.1:5000/api/metrics
```

Example verified email endpoint:

```text
POST http://127.0.0.1:5000/api/scan/email
```

## 21. Example Phishing Email Test

Example email:

```text
Subject: Important: Verify Your College Account

Dear User,
We noticed unusual login activity on your college portal account.
To avoid temporary suspension, please verify your account immediately:
http://secure-college-verification-demo.test/login
Failure to verify within 24 hours may result in restricted access.
```

Detected indicators:

- Contains an embedded URL.
- Uses urgent language.
- Uses account verification language.
- Mentions restriction/suspension.
- Contains login-related keyword.
- Uses a suspicious verification domain.

## 22. Advantages

- Works as both a web app and browser extension.
- Provides explainable results.
- Supports email and URL scanning.
- Stores evidence and logs.
- Works offline with local rules.
- Can be enriched with VirusTotal.
- Has a modular architecture.
- ML model support is already integrated.

## 23. Limitations

- Current ML model is basic and should be improved with a larger dataset.
- VirusTotal enrichment requires an API key for live intelligence.
- Gmail DOM structure may change, requiring content script updates.
- Email header analysis is stronger when full `.eml` files are available.
- The system is intended for triage and awareness, not as a complete enterprise mail gateway.

## 24. Future Enhancements

Possible improvements:

- Train a stronger ML model using a larger phishing/legitimate URL dataset.
- Add domain age and WHOIS intelligence.
- Add screenshot-based phishing page detection.
- Add user authentication for dashboard access.
- Add PDF export for reports.
- Add role-based SOC workflows.
- Add browser notification alerts.
- Add automatic Gmail link scanning.
- Add allowlist/blocklist management.
- Add deployment using Docker.

## 25. Conclusion

PhishGuard AI is a complete phishing triage system that combines web-based analysis, browser-based protection, email scanning, URL feature extraction, database logging, and VirusTotal enrichment. The project demonstrates how cybersecurity detection can be made accessible through explainable scoring, practical dashboards, and real-time browser integration.

The system is modular and extensible, making it suitable for academic demonstration, cybersecurity training, and future improvement into a stronger phishing defense platform.

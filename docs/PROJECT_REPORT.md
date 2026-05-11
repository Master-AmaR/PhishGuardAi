# PhishGuard AI: Complete Working Project Report

## 1. Project Title

**PhishGuard AI: Web and Email Phishing Detection, Evidence Logging, and Browser Warning System**

PhishGuard AI is a Flask-based cybersecurity project that detects suspicious URLs and phishing emails. It combines a web dashboard, REST APIs, SQLite evidence storage, heuristic and ML-ready detection logic, VirusTotal reputation enrichment, and a Chrome extension for browser and Gmail scanning.

The project is designed as a practical phishing triage platform. It does not only classify something as safe or suspicious; it also explains why the verdict was produced, stores the evidence in detection logs, and makes the same evidence available in reports.

## 2. Abstract

Phishing attacks use fake login pages, urgent emails, misleading domains, suspicious links, and impersonation to steal credentials or sensitive information. PhishGuard AI addresses this problem by scanning URLs and emails for known phishing indicators, generating a risk score, enriching results with external reputation data, and storing findings for review.

The system has two main user experiences:

- A Flask web application for dashboards, URL scanning, email analysis, logs, and reports.
- A Chrome extension that scans active tabs and Gmail messages through the Flask backend.

The backend stores URL scans, email scans, detection logs, and learned email pattern signatures in SQLite. The detection log now contains a detailed explanation of each event, including important indicators, action taken, scan source, and learned pattern profile.

## 3. Problem Statement

Phishing is difficult for normal users to identify because attackers make malicious pages and emails look legitimate. Common attack patterns include:

- Fake login pages.
- Urgent account verification messages.
- Password reset or account suspension warnings.
- URLs containing trusted brand names but hosted on unrelated domains.
- HTTP links without HTTPS.
- URL shorteners hiding the final destination.
- Emails with weak or failed SPF, DKIM, or DMARC authentication.
- Messages that pressure the user to click a link quickly.

The goal of this project is to provide an explainable phishing detection system that can scan both websites and emails, show risk indicators, and preserve evidence for later review.

## 4. Main Objectives

- Detect suspicious URLs using local feature extraction.
- Analyze email content for phishing indicators.
- Extract URLs from emails and check URL reputation.
- Use VirusTotal reputation data when an API key is configured.
- Store all scan results in SQLite.
- Keep a unified detection log for URL scans, email scans, and extension scans.
- Display detailed explanations in Detection Logs and Reports.
- Provide a live dashboard with metrics and a threat activity timeline.
- Add an all-time timeline view for complete scan history.
- Store learned email pattern signatures so repeated email patterns can influence future scoring.
- Provide a Chrome extension for active page and Gmail scanning.

## 5. Technology Stack

### Backend

- **Python**: Core backend language.
- **Flask**: Web framework for pages and REST APIs.
- **SQLite**: Local database for scan history and evidence.
- **Werkzeug**: Secure file upload filename handling.
- **python-dotenv**: Loads environment variables from `.env`.
- **requests**: Used for VirusTotal API calls.

### Detection and ML Support

- **Custom heuristic scoring**: Primary detection method for URLs and emails.
- **joblib**: Loads a trained URL model from `ml_models/url_model.joblib`.
- **scikit-learn**: Used by the model training script.
- **RandomForestClassifier**: Used in the URL model training pipeline.
- **DictVectorizer**: Converts extracted URL features into ML model input.

### Frontend

- **Jinja templates**: Flask-rendered HTML pages.
- **Custom CSS**: Dashboard, scanner, logs, and report styling.
- **Bootstrap Icons**: Icons used across the interface.
- **Chart.js**: Threat activity timeline chart.
- **JavaScript Fetch API**: Calls backend scan and metrics APIs.

### Browser Extension

- **Chrome Extension Manifest V3**.
- **Service worker background script**.
- **Content scripts** for websites and Gmail.
- **Chrome APIs**: `tabs`, `storage`, `runtime`, and `action`.

### External Intelligence

- **VirusTotal API v3** for URL reputation.
- Offline fallback response when no API key is configured.

## 6. High-Level Architecture

```text
User
  |
  |-- Flask Web Dashboard
  |     |-- URL Scanner
  |     |-- Email Analyzer
  |     |-- Detection Logs
  |     |-- Reports
  |
  |-- Chrome Extension
        |-- Active tab scanner
        |-- Website warning banner
        |-- Gmail scan button

Both clients call:

Flask API Layer
  |
  |-- ML and heuristic detection service
  |-- VirusTotal reputation service
  |-- Repository/database layer
  |
SQLite Database
  |
  |-- url_scans
  |-- email_scans
  |-- detection_logs
  |-- threat_reports
  |-- learned_email_patterns
```

## 7. End-to-End Working Flow

### URL Scan Flow

1. User enters a URL in the dashboard or scans a page from the Chrome extension.
2. Backend validates the URL.
3. `predict_url()` extracts URL features.
4. Local heuristic scoring calculates a threat score.
5. If a trained model exists, model prediction is also used.
6. VirusTotal reputation lookup is performed.
7. A final classification, severity, confidence, and action are generated.
8. URL scan is stored in `url_scans`.
9. A detailed detection log is stored in `detection_logs`.
10. Dashboard, timeline, logs, and reports become updated.

### Email Scan Flow

1. User pastes email content, uploads `.eml` or `.txt`, or scans a Gmail message through the extension.
2. Backend parses headers and body text.
3. URLs, domains, suspicious terms, sender, subject, Reply-To, authentication headers, and spam headers are extracted.
4. Email risk score is calculated.
5. URLs inside the email are checked with VirusTotal, up to the configured quota-friendly limit.
6. Important indicators are generated.
7. A learned email pattern signature is created and stored.
8. Email scan is stored in `email_scans`.
9. A detailed detection log is stored in `detection_logs`.
10. The result appears in the dashboard, logs, reports, or Gmail result panel.

## 8. Project Folder Structure

```text
TTL-project/
|-- app.py
|-- config.py
|-- requirements.txt
|-- README.md
|-- database/
|   |-- __init__.py
|   |-- db.py
|   |-- schema.sql
|-- models/
|   |-- __init__.py
|   |-- repositories.py
|-- routes/
|   |-- __init__.py
|   |-- api.py
|   |-- dashboard.py
|-- services/
|   |-- __init__.py
|   |-- ml_service.py
|   |-- virustotal_service.py
|-- utils/
|   |-- __init__.py
|   |-- validators.py
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
|-- scripts/
|   |-- train_url_model.py
|-- ml_models/
|   |-- url_model.joblib
|-- docs/
|   |-- PROJECT_REPORT.md
|   |-- PPT_OUTLINE.md
|   |-- PROJECT_PRESENTATION_GUIDE.md
|-- logs/
|-- uploads/
|-- phishguard-chrome-extension/
|   |-- manifest.json
|   |-- background.js
|   |-- content.js
|   |-- gmail_content.js
|   |-- popup.html
|   |-- popup.css
|   |-- popup.js
|   |-- README.md
```

## 9. File-by-File Purpose

### Root Files

#### `app.py`

Creates the Flask application.

Responsibilities:

- Instantiates the Flask app.
- Loads configuration from `Config`.
- Initializes the SQLite database.
- Registers dashboard routes.
- Registers API routes under `/api`.
- Starts the development server on `127.0.0.1:5000`.

Important function:

- `create_app(config_class=Config)`: Central Flask application factory.

#### `config.py`

Stores application configuration.

Important settings:

- `SECRET_KEY`: Flask secret key.
- `DATABASE`: SQLite database path.
- `VIRUSTOTAL_API_KEY`: Optional VirusTotal key.
- `UPLOAD_FOLDER`: Upload directory.
- `MAX_CONTENT_LENGTH`: Maximum accepted upload size.
- `ALLOWED_EMAIL_EXTENSIONS`: Allowed email uploads: `.eml`, `.txt`.
- `ML_MODEL_PATH`: Path to `ml_models/url_model.joblib`.
- `LOG_FILE`: Log file path.

#### `requirements.txt`

Lists Python dependencies:

- Flask
- python-dotenv
- requests
- joblib
- scikit-learn
- email-validator

#### `README.md`

Short project introduction, setup instructions, API examples, and notes.

### Package Marker Files

#### `database/__init__.py`

Marks `database/` as a Python package.

#### `models/__init__.py`

Marks `models/` as a Python package.

#### `routes/__init__.py`

Marks `routes/` as a Python package.

#### `services/__init__.py`

Marks `services/` as a Python package.

#### `utils/__init__.py`

Marks `utils/` as a Python package.

These files do not contain business logic, but they make imports cleaner and keep the project organized as packages.

### Documentation Files

#### `docs/PROJECT_REPORT.md`

This complete working project report.

#### `docs/PPT_OUTLINE.md`

Slide-by-slide outline for creating a project presentation.

#### `docs/PROJECT_PRESENTATION_GUIDE.md`

Presentation speaking guide and explanation support for demonstrating the project.

### Runtime and Artifact Folders

#### `ml_models/url_model.joblib`

Serialized trained URL model loaded by `services/ml_service.py` when available.

#### `uploads/`

Reserved folder for uploaded email files or future uploaded artifacts.

#### `logs/`

Stores runtime log files such as server output files.

#### `myvenv/`

Local Python virtual environment. This is not application source code, but it contains installed project dependencies for local execution.

## 10. Database Layer

### `database/db.py`

Manages SQLite connection and database initialization.

Main functions:

- `get_db()`: Opens and returns a SQLite connection stored in Flask `g`.
- `close_db()`: Closes the connection after request context ends.
- `init_db(app)`: Runs schema creation and upgrades.
- `ensure_schema_upgrades(db)`: Adds newer columns to existing databases without deleting user history.

The upgrade function is important because existing database files may not have newer columns such as `summary_text`, `indicators_json`, and `pattern_json`.

### `database/schema.sql`

Defines all database tables.

#### `url_scans`

Stores individual URL scans.

Columns:

- `id`
- `target_url`
- `classification`
- `threat_score`
- `ml_confidence`
- `vt_detection_ratio`
- `features_json`
- `created_at`

#### `email_scans`

Stores individual email scans.

Columns:

- `id`
- `sender`
- `subject`
- `extracted_urls`
- `classification`
- `threat_score`
- `ml_confidence`
- `suspicious_terms`
- `created_at`

#### `detection_logs`

Stores unified event logs for URL, email, dashboard, and extension scans.

Columns:

- `id`
- `target_source`
- `severity`
- `threat_type`
- `ai_confidence`
- `scan_source`
- `action_taken`
- `summary_text`
- `indicators_json`
- `pattern_json`
- `created_at`

This table powers the Detection Logs page, CSV export, Reports page, recent logs API, and dashboard streams.

#### `threat_reports`

Reserved for saved report-style summaries.

Columns:

- `id`
- `title`
- `summary`
- `severity`
- `source`
- `created_at`

#### `learned_email_patterns`

Stores repeated email pattern signatures.

Columns:

- `id`
- `pattern_key`
- `pattern_label`
- `severity`
- `observation_count`
- `confidence_total`
- `indicators_json`
- `first_seen`
- `last_seen`

Purpose:

- Every email scan generates a pattern signature.
- If the same pattern appears again, observation count increases.
- Repeated suspicious patterns can raise future email scores.
- Repeated benign patterns can slightly reduce future scores.

## 11. Repository Layer

### `models/repositories.py`

This file is the database access layer. Routes do not write SQL directly; they call repository functions.

Main functions:

- `create_url_scan(result, scan_source="URL Scanner")`
- `create_email_scan(result, scan_source="Email Analyzer")`
- `create_detection_log(...)`
- `upsert_email_pattern(result, commit=True)`
- `list_recent_logs(limit=8)`
- `list_all_logs()`
- `dashboard_metrics()`
- `severity_counts()`
- `threat_timeline(window="live")`
- `list_active_threats(limit=3)`

Important behavior:

- URL scans create rows in both `url_scans` and `detection_logs`.
- Email scans create rows in `email_scans`, `detection_logs`, and `learned_email_patterns`.
- Detection logs are enriched before display.
- Older logs that do not have stored indicator JSON are given fallback indicators by analyzing the stored target URL again.
- Timeline supports `live`, `24h`, `7d`, and `all`.

### Timeline Windows

- `live`: Last 12 five-minute buckets.
- `24h`: Last 24 hourly buckets.
- `7d`: Last 7 daily buckets.
- `all`: Entire database history. Uses daily buckets for normal history and monthly buckets if history becomes large.

## 12. Dashboard Routes

### `routes/dashboard.py`

Defines routes for web pages.

#### `GET /`

Renders the main dashboard.

Purpose:

- Shows metrics.
- Shows threat activity timeline.
- Shows severity matrix.
- Shows rapid URL triage.
- Shows recent detection stream.
- Shows active threat intelligence.

#### `GET /url-scanner`

Renders the manual URL scanner page.

Purpose:

- Accept URL input.
- Display verdict, confidence, URL features, VirusTotal information, and indicators.

#### `GET /email-analyzer`

Renders the email analyzer page.

Purpose:

- Paste raw email content.
- Upload `.eml` or `.txt`.
- Display email metadata, extracted URLs, suspicious terms, and reasons.

#### `GET /logs`

Renders Detection Logs.

Purpose:

- Show every logged scan.
- Expand rows for detailed explanation.
- Show what happened, important indicators, scan source, and learned pattern profile.
- Search and filter events.

#### `GET /reports`

Renders the Threat Reports page.

Purpose:

- Generate a report-ready view of recent evidence.
- Display risk rating, primary vector, recommended action, confidence, and event explanations.
- Browser print can be used to export PDF.

#### `GET /logs/export.csv`

Exports detection logs as CSV.

CSV includes:

- Timestamp
- Target/source
- Severity
- Threat type
- Confidence
- Scan source
- Action
- Summary
- Important indicators

## 13. API Routes

### `routes/api.py`

Defines JSON and form-based API endpoints.

### `GET /api/metrics`

Purpose:

- Returns dashboard metric counts.

Response example:

```json
{
  "metrics": {
    "total_scans": 42,
    "phishing_detections": 31,
    "active_threats": 12,
    "ml_accuracy": 71.4
  }
}
```

### `GET /api/timeline?range=live`

Purpose:

- Returns timeline labels and values for Chart.js.

Supported ranges:

- `live`
- `24h`
- `7d`
- `all`

Example:

```http
GET /api/timeline?range=all
```

Response:

```json
{
  "timeline": {
    "labels": ["05/07", "05/08", "05/09"],
    "values": [26, 30, 4]
  }
}
```

### `GET /api/logs/recent`

Purpose:

- Returns the 10 most recent enriched detection logs.

Used by:

- Dashboard refreshes.
- Possible automation or future frontend widgets.

### `GET /api/reports/snapshot`

Purpose:

- Returns report data for live report refresh before printing.

Response includes:

- Metrics
- Severity counts
- Recent logs
- Generated timestamp

### `POST /api/scan/url`

Purpose:

- Main URL scanning endpoint.
- Used by dashboard URL scanner and Chrome extension.
- Stores scan result in `url_scans`.
- Stores detailed detection event in `detection_logs`.

Request:

```json
{
  "url": "http://example-login.test/account/verify"
}
```

Extension request:

```json
{
  "url": "http://example-login.test/account/verify",
  "scan_source": "extension"
}
```

Response includes:

- `target`
- `classification`
- `threat_score`
- `ml_confidence`
- `severity`
- `action`
- `summary`
- `important_indicators`
- `pattern_profile`
- `features`
- `virustotal`
- `vt_detection_ratio`

### `POST /api/scan/email`

Purpose:

- Main email scanning endpoint.
- Accepts pasted email content or uploaded `.eml`/`.txt`.
- Used by the Email Analyzer page and Gmail extension.
- Stores scan result in `email_scans`.
- Stores detection event in `detection_logs`.
- Updates `learned_email_patterns`.

Form fields:

- `content`: Raw email content.
- `email_file`: Optional uploaded `.eml` or `.txt`.
- `scan_source=extension`: Optional marker used by Gmail extension.

Response includes:

- `sender`
- `subject`
- `reply_to`
- `authentication_results`
- `sender_ip`
- `classification`
- `threat_score`
- `ml_confidence`
- `severity`
- `action`
- `suspicious_terms`
- `extracted_urls`
- `evidence_urls`
- `unique_domains`
- `unique_evidence_domains`
- `shortened_urls`
- `reasons`
- `summary`
- `important_indicators`
- `pattern_profile`
- `url_reputation`

### `POST /api/intel/reputation`

Purpose:

- Lightweight reputation endpoint.
- Returns heuristic URL result plus VirusTotal result.
- Kept for compatibility and external lookup use.

Request:

```json
{
  "target": "https://example.com"
}
```

Response:

```json
{
  "target": "https://example.com",
  "heuristic": {},
  "virustotal": {}
}
```

Note:

- The Chrome extension now uses `/api/scan/url` for active tab scans so those scans are stored in Detection Logs.

## 14. Detection and ML Service

### `services/ml_service.py`

This is the main detection logic file.

It handles:

- URL feature extraction.
- URL heuristic scoring.
- Optional trained model loading.
- URL indicator generation.
- Email parsing.
- Email phishing scoring.
- Email pattern signature generation.
- Learned email pattern lookup.

## 15. URL Detection Working

### URL Feature Extraction

Function:

- `extract_url_features(target_url)`

Extracted features:

- `url_length`: Total URL length.
- `https_enabled`: Whether scheme is HTTPS.
- `suspicious_characters`: Counts `@`, `-`, `_`, `%`.
- `query_param_count`: Number of query parameters.
- `tracking_param_count`: Known tracking parameters.
- `redirect_markers`: Parameters such as `url`, `redirect`, `return_url`, `next`.
- `ip_based_url`: Whether host is an IP address.
- `domain`: Parsed host.
- `subdomain_depth`: Depth of subdomains.
- `trusted_shopping_domain`: Whether host matches known shopping domains.
- `known_marketplace_pattern`: Whether URL matches known marketplace product patterns.
- `keyword_hits`: Suspicious terms found in host or path.

### URL Scoring

Function:

- `predict_url(target_url)`

Base scoring logic:

- Starts from a small base score.
- Adds score for long URLs.
- Adds score for missing HTTPS.
- Adds score for suspicious characters.
- Adds score for non-tracking query parameters.
- Adds score for redirect markers.
- Adds score for IP-based hosts.
- Adds score for deep subdomain chains.
- Adds score for phishing keyword hits.

Risk reduction:

- Trusted shopping domains can reduce score.
- Known marketplace product patterns can reduce score.
- A confident trained model prediction of legitimate can reduce score.

### URL Classification Thresholds

| Score Range | Classification | Severity | Action |
| --- | --- | --- | --- |
| 0-34 | Benign | Low | ALLOWED |
| 35-54 | Potentially Suspicious | Medium | LOGGED |
| 55-79 | Suspicious Phishing | High | QUARANTINED |
| 80-99 | Credential Harvesting Phishing | Critical | BLOCKED |

### URL Explanation Output

The URL scanner returns:

- Human-readable summary.
- Important indicators.
- Pattern profile.
- Raw extracted features.

Example indicators:

- Missing HTTPS increases interception and impersonation risk.
- URL structure contains suspicious symbols.
- Query string contains redirect markers.
- Domain has deep subdomain nesting.
- Phishing keyword matches were found.
- Final URL threat score is shown.

## 16. Trained URL Model

### Model Loading

Function:

- `load_url_model()`

The model is loaded from:

```text
ml_models/url_model.joblib
```

If the model file exists, `joblib.load()` loads it. If not, heuristic detection still works.

### Model Input

Function:

- `url_model_features(features)`

The model receives structured numeric features:

- URL length
- HTTPS flag
- Suspicious character count
- Query parameter count
- Tracking ratio
- Redirect markers
- IP-based URL flag
- Subdomain depth
- Trusted shopping domain flag
- Known marketplace pattern flag
- Keyword count

### Model Training Script

File:

- `scripts/train_url_model.py`

Working:

1. Reads known legitimate URL patterns from a text file.
2. Generates suspicious variants using fake login, account update, IP-based, and redirect patterns.
3. Extracts features using `extract_url_features()`.
4. Converts features using `DictVectorizer`.
5. Trains a `RandomForestClassifier`.
6. Saves the trained pipeline to `ml_models/url_model.joblib`.

Command format:

```powershell
.\myvenv\Scripts\python.exe scripts\train_url_model.py patterns.txt --output ml_models\url_model.joblib
```

Current role of the model:

- The project is fully functional with heuristic scoring.
- The trained model is an enhancement layer.
- If the model exists, its label and confidence can adjust the final URL score.

## 17. Email Detection Working

### Email Parsing

Function:

- `analyze_email_content(content)`

The email parser extracts:

- Sender
- Subject
- Reply-To
- Authentication-Results
- X-Microsoft-Antispam
- X-Sender-IP
- X-MS-Exchange-Organization-SCL
- Decoded text body
- URLs in body

### Email Indicators

The scanner checks for:

- Embedded URLs.
- Multiple evidence domains.
- URL shorteners.
- Suspicious language.
- Reply-To mismatch.
- SPF, DKIM, or DMARC failure.
- Weak authentication results.
- Composite authentication failure.
- DKIM missing.
- Sender IP presence.
- Elevated Microsoft spam confidence level.
- High bulk complaint level.
- Brand impersonation with unrelated domains.

### Suspicious Terms

Examples:

- `account`
- `verify`
- `urgent`
- `password`
- `suspended`
- `restricted`
- `login`
- `update`
- `wallet`
- `invoice`
- `security alert`

### Email Scoring

Base score starts at 18.

Score increases for:

- Number of URLs.
- Number of unique evidence domains.
- URL shorteners.
- Suspicious terms.
- Reply-To mismatch.
- Authentication failures.
- Weak authentication.
- High spam confidence.
- Brand impersonation.
- Repeated learned suspicious patterns.

Score can slightly decrease when a repeated pattern was previously classified as benign.

### Email Classification

| Score Range | Classification | Severity | Action |
| --- | --- | --- | --- |
| 0-59 | Benign | Low | ALLOWED |
| 60-74 | Email Phishing | Medium | QUARANTINED |
| 75-98 | Email Phishing | High | QUARANTINED |

### Learned Email Patterns

Every email creates a pattern key based on:

- Suspicious terms.
- Evidence domain count.
- URL shortener count.
- Reply-To mismatch.
- Weak authentication.
- Failed authentication.
- URL count.

The pattern is hashed into a `pattern_key`.

If the same pattern appears again:

- Observation count increases.
- Previous label is stored.
- Future scans can use the repeated pattern as an additional signal.

This makes the project stronger over time because repeated phishing structures become part of the local decision context.

## 18. VirusTotal Service

### `services/virustotal_service.py`

This file handles external URL reputation.

Main class:

- `VirusTotalService`

Main methods:

- `enabled`: Checks whether API key is configured.
- `_normalize_url(target_url)`: Adds HTTP scheme if missing.
- `_url_id(target_url)`: Creates VirusTotal URL ID.
- `_gui_url(target_url)`: Builds VirusTotal GUI proof link.
- `scan_url(target_url)`: Submits URL to VirusTotal.
- `reputation_lookup(target_url)`: Retrieves existing report or submits URL if unknown.
- `parse_url_report(payload, target_url)`: Extracts malicious, suspicious, harmless, and undetected counts.
- `_submitted_response(payload)`: Handles newly submitted URLs.
- `_error_response(error, target_url)`: Handles API errors safely.
- `_offline_response(target_url)`: Returns fallback when API key is missing.

Offline fallback is important because the project remains usable without a VirusTotal key.

## 19. Validators

### `utils/validators.py`

Functions:

- `is_valid_url(value)`: Checks whether URL/domain has a valid network location and dot.
- `allowed_file(filename, allowed_extensions)`: Checks upload extension.

Used by:

- `/api/scan/url`
- `/api/scan/email`

## 20. Frontend Templates

### `templates/base.html`

Base layout shared by all pages.

Contains:

- HTML skeleton.
- Sidebar navigation.
- Top bar.
- CSS and JS includes.
- Common page blocks.

### `templates/dashboard.html`

Main dashboard.

Contains:

- Metrics cards.
- Threat Activity Timeline.
- Timeline controls: Live, 24H, 7D, All.
- Severity matrix.
- Rapid URL triage form.
- Live detection stream.
- Active threat intelligence cards.

### `templates/url_scanner.html`

Manual URL scanner page.

Contains:

- URL input form.
- Analysis verdict panel.
- Threat score ring.
- VirusTotal status and proof link.
- URL feature cards.
- Indicator list.
- Engine console output.

### `templates/email_analyzer.html`

Email analysis page.

Contains:

- Raw email textarea.
- Email file upload.
- Email verdict panel.
- Metadata grid.
- Suspicious term display.
- URL reputation evidence list.

### `templates/logs.html`

Detection Logs page.

Contains:

- Search box.
- CSV export button.
- Severity filters.
- Expandable log rows.
- What Happened section.
- Important Indicators section.
- Learned Pattern Profile section.

This page now avoids empty explanations by reconstructing indicators for older URL rows when stored indicator JSON is unavailable.

### `templates/reports.html`

Threat report page.

Contains:

- Report cover.
- Risk summary.
- Executive summary.
- ML confidence.
- Recent evidence table.
- Detection explanation column.
- Recommended response.
- Analyst notes.
- Print/PDF workflow.

## 21. Static Frontend Files

### `static/css/style.css`

Contains the complete visual design.

Styles:

- Sidebar.
- Top bar.
- Dashboard cards.
- Scanner panels.
- Timeline and chart containers.
- Tables.
- Detection log detail panels.
- Report layout.
- Responsive mobile behavior.
- Print behavior.

### `static/js/app.js`

Main browser-side JavaScript for the Flask web app.

Responsibilities:

- Escape HTML before rendering dynamic values.
- Initialize Chart.js threat timeline.
- Refresh timeline data from `/api/timeline`.
- Switch timeline ranges.
- Animate dashboard counters.
- Handle sidebar behavior.
- Submit URL scans to `/api/scan/url`.
- Render URL scan results.
- Submit email scans to `/api/scan/email`.
- Render email analysis results.
- Search and filter detection logs.
- Expand and collapse detection log rows.
- Refresh report snapshot before printing.

## 22. Chrome Extension

The extension is located in:

```text
phishguard-chrome-extension/
```

Its purpose is to bring PhishGuard scanning into the browser.

### `manifest.json`

Defines the extension.

Important configuration:

- Manifest version 3.
- Extension name and description.
- Permissions: `storage`, `tabs`.
- Host permissions:
  - All URLs.
  - Gmail.
  - Local Flask backend.
- Background service worker: `background.js`.
- Content scripts:
  - `content.js` for normal websites.
  - `gmail_content.js` for Gmail.
- Popup files:
  - `popup.html`
  - `popup.css`
  - `popup.js`

### `README.md`

Extension-specific notes for installing, configuring, or explaining the Chrome extension.

### `background.js`

Main extension service worker.

Responsibilities:

- Initializes default settings.
- Scans tabs when pages finish loading.
- Scans active tab when extension popup requests it.
- Uses trusted domain checks.
- Uses local heuristic fallback.
- Calls backend `/api/scan/url` when available.
- Marks extension scans with `scan_source: "extension"` so they appear in Detection Logs.
- Caches verdicts.
- Sets warning badge on suspicious tabs.
- Handles Gmail scan messages.
- Sends email content to `/api/scan/email`.

Important result:

- Every backend-backed extension URL scan is now visible in Detection Logs.

### `content.js`

Runs on normal websites.

Responsibilities:

- Receives verdict messages from `background.js`.
- Displays a warning banner when a page is suspicious.
- Shows classification, score, and top reasons.
- Allows user to dismiss the warning.
- Avoids showing warnings on local backend pages.

### `gmail_content.js`

Runs on Gmail.

Responsibilities:

- Adds a floating `Scan with PhishGuard` button.
- Uses a `MutationObserver` so the button remains available as Gmail changes the DOM.
- Detects visible email body.
- Extracts subject, sender, and body text.
- Sends scan request to background worker.
- Displays a result panel inside Gmail.
- Shows safe, medium, danger, or unavailable states.

### `popup.html`

Defines popup structure.

Contains:

- Extension title.
- Verdict box.
- Reason card.
- Scan Active Tab button.

### `popup.css`

Styles the extension popup.

Includes:

- Safe, medium, and danger verdict states.
- Button styling.
- Reason list layout.

### `popup.js`

Controls popup behavior.

Responsibilities:

- Loads last verdict from Chrome storage.
- Automatically scans current page when popup opens.
- Sends `phishguard:scan-active-tab` message to background worker.
- Renders classification, score, and reasons.
- Handles timeout and unavailable states.

## 23. Extension Scan Flow

### Active Tab Scan

1. Chrome tab completes loading.
2. `background.js` checks if URL is scannable.
3. If trusted, a low-risk local verdict is produced.
4. If backend is enabled, extension calls `/api/scan/url`.
5. Backend scans URL and stores it in Detection Logs.
6. Background script receives verdict.
7. If suspicious, browser badge is set and content warning banner is shown.
8. Popup can show the latest verdict.

### Gmail Scan

1. User opens Gmail.
2. `gmail_content.js` injects floating scan button.
3. User opens an email and clicks button.
4. Gmail content script extracts email text.
5. Background script sends content to `/api/scan/email`.
6. Backend scans email and stores log as `Chrome Extension Gmail`.
7. Gmail panel displays classification, score, and reasons.

## 24. Detection Logs and Reports

Detection Logs are a central part of the project.

Each log answers:

- What target or source was scanned?
- When was it scanned?
- Was it safe or suspicious?
- What severity was assigned?
- What confidence was produced?
- What action was taken?
- Which scanner generated it?
- Why was this verdict reached?
- What pattern was learned?

Detailed log fields:

- `summary_text`: Human-readable event summary.
- `indicators_json`: Important evidence reasons.
- `pattern_json`: Pattern profile for URL or email.

Reports use the same enriched log data, so the evidence shown in Detection Logs also appears in the report table.

## 25. All-Time Threat Timeline

The dashboard timeline supports four windows:

- Live
- 24H
- 7D
- All

The `All` view reads every row in `detection_logs`.

Behavior:

- If history is short, it groups by day.
- If history is long, it groups by month.
- It returns labels and values to Chart.js.

This gives a complete project history view instead of only recent scan windows.

## 26. Report Generation

The Reports page is browser-print based.

Working:

1. User opens Reports.
2. Page loads recent logs and summary data.
3. User clicks Generate Live PDF.
4. Frontend calls `/api/reports/snapshot`.
5. Report table refreshes with latest evidence.
6. Browser print dialog opens.
7. User can save as PDF.

## 27. Security Features

- Environment variables are used for secrets.
- VirusTotal key is not hardcoded.
- File uploads are limited to `.eml` and `.txt`.
- Uploaded filenames are sanitized.
- Upload size is limited.
- Frontend dynamic output is escaped.
- API validates URL input.
- Extension avoids warning on localhost backend pages.
- VirusTotal failures return safe structured errors instead of crashing.
- Offline VirusTotal fallback keeps scans functional without a key.

## 28. Example URL Detection

Input:

```text
www.dghjdgf.com/paypal.co.uk/cycgi-bin/webscrcmd=_home-customer&nav=1/loading.php
```

Possible detected indicators:

- Missing HTTPS increases interception and impersonation risk.
- URL structure contains suspicious symbols.
- Suspicious brand-like path is present.
- Final URL threat score is elevated.

Expected output:

- Classification: Suspicious Phishing or Potentially Suspicious.
- Severity: High or Medium.
- Action: QUARANTINED or LOGGED.
- Detection log includes explanation and indicators.

## 29. Example Email Detection

Input:

```text
From: support@example-login.test
Subject: Urgent account verification required
Reply-To: attacker@example.net
Authentication-Results: spf=fail dkim=none dmarc=fail

Your account will be suspended. Verify your password here:
http://secure-login-update.example.test/password/reset
```

Detected indicators:

- Contains embedded URL.
- Suspicious language matched: account, urgent, verify, password, suspended.
- Reply-To differs from From header.
- Authentication headers contain SPF, DKIM, or DMARC failure.
- Authentication results are weak or failed.
- Final score becomes high enough for phishing classification.

Expected output:

- Classification: Email Phishing.
- Severity: High.
- Action: QUARANTINED.
- Pattern is stored in `learned_email_patterns`.

## 30. How to Run the Project

### Install Dependencies

```powershell
python -m venv myvenv
.\myvenv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Configure Environment

Create or update `.env`:

```text
SECRET_KEY=replace-with-secure-key
VIRUSTOTAL_API_KEY=optional-api-key
```

VirusTotal key is optional. The app works without it.

### Start Backend

```powershell
.\myvenv\Scripts\python.exe app.py
```

Open:

```text
http://127.0.0.1:5000
```

## 31. How to Load the Chrome Extension

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Enable Developer Mode.
4. Click Load unpacked.
5. Select:

```text
phishguard-chrome-extension/
```

6. Keep Flask backend running at:

```text
http://127.0.0.1:5000
```

7. Open a website or Gmail and use the extension.

## 32. Testing and Verification

Recommended checks:

### Compile Python

```powershell
.\myvenv\Scripts\python.exe -m compileall app.py database models routes services utils
```

### Test Metrics API

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/metrics
```

### Test All-Time Timeline

```powershell
Invoke-RestMethod "http://127.0.0.1:5000/api/timeline?range=all"
```

### Test URL Scan

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:5000/api/scan/url `
  -ContentType "application/json" `
  -Body '{"url":"http://secure-login-example.test/account/verify"}'
```

### Test Email Scan

```powershell
curl.exe -X POST http://127.0.0.1:5000/api/scan/email `
  -F "content=From: test@example.com`nSubject: urgent verify account`n`nClick http://bad-login.test/password"
```

## 33. Strengths of the Project

- Complete web dashboard and extension integration.
- URL and email phishing detection in one project.
- Explainable results instead of only raw classification.
- SQLite evidence storage.
- All scans are visible in Detection Logs.
- Chrome extension scans are logged.
- Gmail scans are logged.
- Reports reuse the same evidence as logs.
- VirusTotal integration adds external intelligence.
- Offline fallback keeps the system usable.
- Learned email pattern storage improves repeated-pattern decisions.
- Modular Flask architecture makes future enhancements easier.

## 34. Current Limitations

- The URL model depends on available training data quality.
- Heuristic scoring is explainable but can still produce false positives or false negatives.
- VirusTotal live reputation requires an API key.
- Gmail DOM selectors may need updates if Gmail changes its interface.
- Email analysis is strongest with full raw email headers.
- The project is a triage and awareness platform, not a full enterprise mail gateway.
- There is no user authentication yet for the dashboard.

## 35. Future Enhancements

- Add user login and role-based access.
- Add admin settings for thresholds and allowlists.
- Add domain age and WHOIS intelligence.
- Add screenshot or page-content phishing detection.
- Add automatic Gmail link scanning.
- Add blocklist and allowlist management.
- Add saved incident reports in `threat_reports`.
- Add PDF generation on backend.
- Add Docker deployment.
- Add model retraining workflow using stored scan data.
- Add feedback buttons: correct/incorrect verdict.
- Add notification alerts for high-risk extension scans.

## 36. Conclusion

PhishGuard AI is a complete phishing detection and triage system. It combines a Flask backend, SQLite evidence storage, URL and email analysis, VirusTotal enrichment, detailed detection logs, report generation, and a Chrome extension.

The strongest part of the project is explainability. Each scan can show what happened, why it was suspicious or safe, what indicators were detected, what action was taken, and whether a pattern was learned. This makes the project useful not only as a scanner, but also as a cybersecurity learning, investigation, and reporting tool.

With the latest updates, the project now supports detailed detection logs, all-time timeline analysis, extension scan logging, Gmail scan logging, and learned email pattern storage. These improvements make the system more complete, more auditable, and stronger for future ML-based decision making.

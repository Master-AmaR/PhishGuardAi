# PhishGuard AI Presentation Guide

This guide explains the project file by file and gives simple answers for common panel or viva questions.

## 1. One-Minute Project Explanation

PhishGuard AI is a phishing detection and triage system. It detects suspicious URLs and suspicious emails using URL feature extraction, heuristic scoring, an optional scikit-learn URL model, VirusTotal reputation checking, and a Chrome extension.

The Flask web app is the main backend. It provides the dashboard, scanners, logs, reports, and REST APIs. The Chrome extension connects to the Flask backend to scan active web pages and Gmail emails. All scan evidence is stored in SQLite so that the user can review past detections.

## 2. Main Modules

### `app.py`

This is the entry point of the Flask application.

Responsibilities:

- Creates the Flask app.
- Loads configuration from `config.py`.
- Initializes the SQLite database.
- Registers dashboard routes.
- Registers API routes under `/api`.
- Runs the server on `127.0.0.1:5000`.

In presentation:

> `app.py` connects all parts of the backend. It starts Flask, prepares the database, and attaches both web page routes and API routes.

### `config.py`

This file stores project settings.

Important settings:

- `SECRET_KEY`: Flask secret key.
- `DATABASE`: SQLite database path.
- `VIRUSTOTAL_API_KEY`: API key for VirusTotal.
- `UPLOAD_FOLDER`: Folder for uploaded email files.
- `MAX_CONTENT_LENGTH`: Maximum upload size, 4 MB.
- `ALLOWED_EMAIL_EXTENSIONS`: Only `.eml` and `.txt` files are allowed.
- `ML_MODEL_PATH`: Path of the trained URL model, `ml_models/url_model.joblib`.

In presentation:

> `config.py` keeps configuration separate from business logic. Sensitive values like the VirusTotal API key are loaded from environment variables.

### `database/db.py`

This file manages SQLite database connections.

Responsibilities:

- Opens a database connection when needed.
- Stores the connection in Flask's `g` object.
- Closes the connection after the request.
- Runs `schema.sql` to create tables if they do not exist.

In presentation:

> `database/db.py` is responsible for database lifecycle management. It ensures tables exist and every request gets a proper SQLite connection.

### `database/schema.sql`

This file defines the database tables.

Tables:

- `url_scans`: Stores URL scan result, classification, score, confidence, VirusTotal ratio, and extracted features.
- `email_scans`: Stores email scan result, sender, subject, extracted URLs, classification, score, and suspicious terms.
- `detection_logs`: Stores unified logs from both URL and email scans.
- `threat_reports`: Reserved for report-style threat summaries.

In presentation:

> The database stores both raw scan history and a unified detection log so the dashboard and report page can show evidence.

### `models/repositories.py`

This file contains database query functions.

Responsibilities:

- Inserts URL scan records.
- Inserts email scan records.
- Creates unified detection logs.
- Reads recent logs.
- Calculates dashboard metrics.
- Calculates severity counts.
- Builds timeline chart data.
- Lists active threats.

In presentation:

> Repository functions separate database operations from route logic. Routes call these functions instead of writing SQL directly everywhere.

### `routes/dashboard.py`

This file handles normal web pages.

Routes:

- `/`: Dashboard.
- `/url-scanner`: URL scanner page.
- `/email-analyzer`: Email analyzer page.
- `/logs`: Detection logs page.
- `/reports`: Report page.
- `/logs/export.csv`: Exports logs as CSV.

In presentation:

> `routes/dashboard.py` renders the user interface pages. It gets data from the repository layer and sends it to Jinja templates.

### `routes/api.py`

This file provides REST API endpoints.

Important endpoints:

- `GET /api/metrics`: Dashboard counters.
- `GET /api/timeline`: Threat timeline chart data.
- `GET /api/logs/recent`: Recent detection logs.
- `GET /api/reports/snapshot`: Report page live snapshot.
- `POST /api/scan/url`: Scans a URL.
- `POST /api/scan/email`: Scans email text or uploaded email file.
- `POST /api/intel/reputation`: Used by the Chrome extension for active tab scanning.

In presentation:

> `routes/api.py` is the communication layer for scanners, dashboard updates, and the Chrome extension.

## 3. Detection and ML Explanation

### `services/ml_service.py`

This is the main detection logic file.

Despite the name `ml_service`, it contains two types of logic:

1. Rule-based heuristic scoring.
2. Optional machine-learning model support for URL classification.

#### URL Features Extracted

For each URL, the system extracts:

- URL length.
- Whether HTTPS is enabled.
- Suspicious characters like `@`, `-`, `_`, `%`.
- Number of query parameters.
- Number of tracking parameters.
- Redirect markers like `url`, `redirect`, `next`, `return_url`.
- Whether host is an IP address.
- Domain name.
- Subdomain depth.
- Suspicious keyword hits.
- Trusted shopping domain check.
- Known marketplace URL pattern check.

#### URL Scoring

The URL starts with a base score and risk is added for suspicious indicators:

- Missing HTTPS adds risk.
- IP-based host adds risk.
- Suspicious characters add risk.
- Redirect markers add risk.
- Deep subdomain chains add risk.
- Phishing keywords add risk.

Score ranges:

- `0-34`: Benign / Low.
- `35-54`: Potentially Suspicious / Medium.
- `55-79`: Suspicious Phishing / High.
- `80-99`: Credential Harvesting Phishing / Critical.

#### What ML Is Used?

The project uses scikit-learn for URL classification support.

The training script uses:

- `DictVectorizer`: Converts extracted feature dictionaries into numeric vectors.
- `RandomForestClassifier`: Learns to classify URLs as `legit` or `suspicious`.
- `Pipeline`: Combines vectorization and classifier into one model.
- `joblib`: Saves and loads the trained model.

The saved model is:

```text
ml_models/url_model.joblib
```

Important presentation point:

> The URL model is a Random Forest classifier trained on extracted URL features. The final scan result also uses heuristic scoring, so the system is explainable and works even if the model file is missing.

#### Email Detection

Email analysis is rule-based. It parses the email and checks:

- Sender.
- Subject.
- Reply-To.
- Authentication results.
- Microsoft anti-spam headers.
- Sender IP.
- Body text.
- Extracted URLs.
- Unique domains.
- URL shorteners.
- Suspicious terms.
- Brand impersonation.

Email scoring increases when:

- Email contains suspicious URLs.
- Multiple domains are used.
- URL shorteners are found.
- Suspicious terms like `verify`, `urgent`, `password`, `login`, `suspended` appear.
- Reply-To differs from From.
- SPF, DKIM, or DMARC failures appear.
- Spam confidence level is high.

Important presentation point:

> Email detection does not currently use a trained ML model. It uses explainable rule-based phishing triage. The `ml_confidence` value is a triage confidence score derived from the threat score.

### `scripts/train_url_model.py`

This script trains the URL model.

How it works:

- Reads legitimate URL patterns from a text file.
- Generates suspicious variants of those URLs.
- Extracts features using `extract_url_features`.
- Converts features using `DictVectorizer`.
- Trains a `RandomForestClassifier`.
- Saves the model with `joblib`.

In presentation:

> The ML model is trained using URL feature dictionaries. The classifier is Random Forest because it works well with structured features and is easier to explain than deep learning.

## 4. VirusTotal Integration

### `services/virustotal_service.py`

This file connects the system with VirusTotal API v3.

Responsibilities:

- Normalizes URLs.
- Creates VirusTotal URL IDs.
- Looks up existing URL reputation.
- Submits URL if VirusTotal has no existing record.
- Parses malicious, suspicious, harmless, and undetected counts.
- Generates a VirusTotal GUI report link.
- Returns offline fallback when API key is not configured.

In presentation:

> VirusTotal is used as external threat intelligence. If the API key is not available, the project still works using local detection rules.

## 5. Frontend Files

### `templates/base.html`

Common layout for all pages.

Usually contains:

- Sidebar.
- Navigation.
- Shared CSS and JS imports.
- Bootstrap and icon setup.
- Main content block.

### `templates/dashboard.html`

Main SOC-style dashboard.

Shows:

- Total scans.
- Phishing detections.
- Active threats.
- Average confidence.
- Timeline chart.
- Recent detection logs.
- Active threats.

### `templates/url_scanner.html`

Manual URL scanning page.

Shows:

- URL input form.
- Verdict.
- Threat score.
- URL features.
- VirusTotal status.
- Indicators.

### `templates/email_analyzer.html`

Manual email analysis page.

Supports:

- Pasting raw email content.
- Uploading `.eml` or `.txt` files.
- Showing sender, subject, URLs, domains, reasons, and URL reputation.

### `templates/logs.html`

Shows all detection logs.

Supports:

- Searching.
- Filtering.
- Expanding log details.
- Exporting logs through `/logs/export.csv`.

### `templates/reports.html`

This is the report panel/page.

Shows:

- Executive summary.
- Risk rating.
- Primary vector.
- Recommended action.
- Evidence count.
- ML confidence average.
- Recent evidence table.
- Recommended response.
- Analyst notes.
- Print/PDF generation button.

In presentation:

> The report page converts detection logs into an executive-ready report. It can be printed or saved as PDF from the browser.

### `static/js/app.js`

Main frontend JavaScript.

Responsibilities:

- Initializes threat timeline chart using Chart.js.
- Refreshes dashboard timeline through `/api/timeline`.
- Handles URL scan form submission.
- Handles email scan form submission.
- Renders scan results dynamically.
- Handles log search and filters.
- Refreshes report snapshot before printing.

### `static/css/style.css`

Controls visual design:

- Cybersecurity dashboard theme.
- Sidebar.
- Cards.
- Tables.
- Forms.
- Report layout.
- Responsive design.

## 6. Chrome Extension Files

### `phishguard-chrome-extension/manifest.json`

Defines the Chrome extension.

Important points:

- Uses Manifest V3.
- Uses `background.js` as service worker.
- Injects `content.js` into normal web pages.
- Injects `gmail_content.js` into Gmail.
- Uses permissions such as `storage` and `tabs`.
- Allows access to local backend `http://127.0.0.1:5000`.

### `background.js`

Main extension service worker.

Responsibilities:

- Scans active browser tabs.
- Sends URLs to Flask backend.
- Uses local heuristic fallback if backend is unavailable.
- Maintains a verdict cache.
- Updates extension badge.
- Handles Gmail scan messages.

In presentation:

> The background script is the bridge between the browser and Flask backend.

### `content.js`

Runs on normal websites.

Responsibilities:

- Receives verdicts from `background.js`.
- Shows a warning banner if the page looks suspicious.
- Removes warning banner for safe pages.

### `gmail_content.js`

Runs on Gmail.

Responsibilities:

- Adds a floating "Scan with PhishGuard" button.
- Detects visible email body, sender, and subject.
- Sends email content to the extension background script.
- Displays the scan result inside Gmail.
- Shows a helpful message if no email is open.

### `popup.html`, `popup.css`, `popup.js`

These files create the extension popup.

Responsibilities:

- Shows current page status.
- Allows manual active tab scan.
- Displays score and reasons.

## 7. Utility Files

### `utils/validators.py`

Contains validation helpers:

- `is_valid_url`: Checks whether input looks like a valid URL or domain.
- `allowed_file`: Checks uploaded file extension.

### `requirements.txt`

Lists Python dependencies:

- Flask.
- python-dotenv.
- requests.
- joblib.
- scikit-learn.
- email-validator.

### `README.md`

Contains setup instructions, feature list, API examples, and project overview.

### `docs/PROJECT_REPORT.md`

Main detailed project report.

### `docs/PPT_OUTLINE.md`

Presentation slide outline.

## 8. End-to-End Flow

### URL Scan Flow

1. User enters URL on web page or opens a site in Chrome.
2. Frontend or extension sends URL to Flask API.
3. `routes/api.py` receives request.
4. `predict_url` in `ml_service.py` extracts features and scores risk.
5. Optional URL model is loaded from `ml_models/url_model.joblib`.
6. VirusTotal reputation is checked.
7. Result is saved to SQLite.
8. Detection log is created.
9. Dashboard, logs, and report page update.

### Email Scan Flow

1. User pastes email, uploads `.eml/.txt`, or scans Gmail email.
2. Flask API receives email content.
3. `analyze_email_content` parses email headers and body.
4. URLs and suspicious terms are extracted.
5. Local phishing score is calculated.
6. Extracted URLs are checked with VirusTotal.
7. Result is saved to SQLite.
8. User gets verdict with clear reasons.

## 9. How To Explain The ML Clearly

Use this wording:

> In this project, ML is used for URL classification support. We extract structured URL features such as URL length, HTTPS status, query parameters, redirect markers, IP-based host, subdomain depth, and phishing keywords. These features are converted into numeric vectors using `DictVectorizer`, and a `RandomForestClassifier` is trained to classify URLs as legitimate or suspicious. The model is saved using `joblib` and loaded during scanning. Along with this, we use heuristic scoring so the system remains explainable and works even without the trained model.

Also say:

> Email scanning is currently rule-based, not trained ML. It checks suspicious words, sender mismatch, authentication failures, URL shorteners, multiple domains, and phishing-style language.

## 10. Likely Viva Questions and Answers

### Q1. What problem does your project solve?

It helps users detect phishing URLs and phishing emails before interacting with them. It gives a score, classification, reason, and recommended action.

### Q2. What are the main components?

The main components are Flask backend, SQLite database, detection service, VirusTotal service, dashboard UI, report panel, and Chrome extension.

### Q3. What ML algorithm did you use?

For URL classification support, the project uses a scikit-learn `RandomForestClassifier` inside a `Pipeline` with `DictVectorizer`.

### Q4. Why Random Forest?

Random Forest works well for structured tabular features, handles non-linear patterns, is robust for small feature sets, and is easier to explain than deep learning.

### Q5. Is email detection ML-based?

No. Email detection is currently rule-based. It uses phishing indicators such as suspicious terms, embedded URLs, URL shorteners, authentication failures, Reply-To mismatch, and brand impersonation.

### Q6. What features are extracted from URLs?

URL length, HTTPS status, suspicious characters, query parameter count, redirect markers, IP-based host, domain, subdomain depth, tracking parameters, trusted shopping domain status, and keyword hits.

### Q7. What is VirusTotal used for?

VirusTotal is used for external reputation enrichment. It checks whether known security engines mark a URL as malicious or suspicious.

### Q8. What happens if VirusTotal API key is missing?

The system still works. It returns an offline fallback response and continues using local heuristic and ML-ready detection.

### Q9. Why SQLite?

SQLite is lightweight, easy to set up, and suitable for a local academic/demo project. It stores scan history, email scans, detection logs, and reports.

### Q10. What is the Chrome extension doing?

It scans active websites and Gmail messages. It sends data to the Flask backend, receives a verdict, and shows warnings or safe results in the browser.

### Q11. How does Gmail scanning work?

The Gmail content script injects a scan button, reads the visible email sender, subject, and body, sends it to the backend, and displays the result in Gmail.

### Q12. What is `ml_confidence`?

It is a triage confidence score shown to the user. For the current rule-based scoring, it is derived from the threat score. For URL model support, there is also `model_confidence` when the trained model is available.

### Q13. What are the limitations?

The URL model is basic, email detection is rule-based, VirusTotal needs an API key for live intelligence, and Gmail DOM changes can affect the content script.

### Q14. What future improvements can be added?

Better URL dataset, stronger ML model, domain age lookup, WHOIS, screenshot analysis, user authentication, PDF export improvement, Docker deployment, allowlist/blocklist, and role-based SOC workflow.

### Q15. Why is the system explainable?

Because each verdict includes reasons such as missing HTTPS, suspicious keywords, embedded URLs, redirect markers, URL shorteners, and authentication header failures.

## 11. Short Presentation Script

Good morning. My project is PhishGuard AI, a web and email phishing detection system. It helps users identify suspicious URLs and emails using local feature extraction, heuristic scoring, optional machine learning support, VirusTotal reputation checking, database logging, and a Chrome extension.

The backend is built with Flask and SQLite. Flask provides the web dashboard and REST APIs, while SQLite stores URL scans, email scans, and detection logs. The main detection logic is in `services/ml_service.py`.

For URLs, the system extracts features like URL length, HTTPS availability, suspicious characters, query parameters, redirect markers, IP-based host, subdomain depth, and phishing keywords. These features are scored using rules, and the project also supports a scikit-learn Random Forest model trained on these extracted features.

For emails, the system parses sender, subject, Reply-To, authentication headers, body text, URLs, domains, URL shorteners, and suspicious terms. It then gives a phishing score and explains the reasons.

The project also integrates VirusTotal. If an API key is available, it checks external reputation. If not, the system continues working with offline local detection.

The Chrome extension extends protection into the browser. It scans active websites and Gmail messages, then shows warnings directly to the user.

Finally, the dashboard and report page provide SOC-style visibility, including total scans, phishing detections, active threats, logs, and report-ready evidence.

## 12. Honest Technical Statement

Use this if the panel asks whether the whole project is ML-based:

> The project is not fully dependent on ML. It is a hybrid system. URL detection has machine-learning support through a scikit-learn Random Forest model, but the final system also uses heuristic scoring for explainability and reliability. Email detection is currently rule-based and can be upgraded to ML in the future.

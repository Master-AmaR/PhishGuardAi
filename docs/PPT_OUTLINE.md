# PhishGuard AI PPT Outline

## Slide 1: Title

Title: PhishGuard AI: Web and Email Phishing Detection System

Subtitle: Flask Dashboard + Chrome Extension + VirusTotal Intelligence

Presented by: Your Name

Speaker notes:
This project detects suspicious URLs and phishing emails using a Flask backend, heuristic/ML-based scoring, VirusTotal reputation checks, and a Chrome extension.

## Slide 2: Problem Statement

Content:

- Phishing is a major cyber threat.
- Attackers use fake login pages and urgent emails.
- Users often fail to identify suspicious links.
- Manual checking is slow and unreliable.

Speaker notes:
The project solves the problem of identifying phishing indicators in websites and emails before users click or submit sensitive information.

## Slide 3: Project Objectives

Content:

- Detect malicious or suspicious URLs.
- Analyze suspicious email content.
- Extract and inspect embedded links.
- Provide explainable reasons for each verdict.
- Store logs and scan history.
- Provide browser-based protection through Chrome extension.

Speaker notes:
The goal is not only detection, but also explanation and evidence collection.

## Slide 4: Technologies Used

Content:

- Python, Flask
- SQLite
- HTML, CSS, JavaScript
- Bootstrap, Bootstrap Icons, Chart.js
- scikit-learn, joblib
- VirusTotal API
- Chrome Extension Manifest V3

Speaker notes:
The project uses a full-stack architecture with backend APIs, frontend dashboard, local database, ML support, external intelligence, and browser integration.

## Slide 5: System Architecture

Content:

User -> Web Dashboard / Chrome Extension -> Flask API -> Analysis Services -> SQLite + VirusTotal

Components:

- Dashboard
- URL Scanner
- Email Analyzer
- Detection Logs
- Chrome Extension
- Gmail Scanner

Speaker notes:
The Chrome extension and web dashboard both communicate with the Flask backend. The backend performs analysis and stores results.

## Slide 6: Project Folder Structure

Content:

- `app.py`: Flask app entry point
- `routes/`: Page and API routes
- `services/`: Detection and VirusTotal logic
- `models/`: Database repository functions
- `database/`: SQLite schema and connection
- `templates/`: Web pages
- `static/`: CSS and JavaScript
- `phishguard-chrome-extension/`: Browser extension

Speaker notes:
The project is modular, so each feature has a clear location.

## Slide 7: URL Detection Workflow

Content:

1. User submits URL.
2. System extracts URL features.
3. Heuristic score is calculated.
4. ML model can be used if available.
5. VirusTotal reputation is checked.
6. Final verdict is displayed and logged.

Speaker notes:
The URL scanner checks both structure and reputation. The score determines the severity.

## Slide 8: URL Features Used

Content:

- URL length
- HTTPS enabled or missing
- Suspicious characters
- Redirect markers
- Query parameters
- IP-based host
- Subdomain depth
- Phishing keywords
- Trusted marketplace patterns

Speaker notes:
These are common indicators in phishing URLs. For example, fake login links often contain words like verify, login, password, and account.

## Slide 9: Email Detection Workflow

Content:

1. User pastes email or opens Gmail message.
2. System extracts sender, subject, body, and links.
3. Suspicious terms are matched.
4. URL domains are extracted.
5. Email headers are checked when available.
6. Verdict and reasons are shown.

Speaker notes:
Email scanning is useful because phishing usually begins with an email message that pressures the user to click a link.

## Slide 10: Email Indicators Used

Content:

- Urgent language
- Account verification requests
- Suspicious links
- Multiple unique domains
- URL shorteners
- Reply-To mismatch
- SPF/DKIM/DMARC failures
- Brand impersonation

Speaker notes:
The system uses explainable indicators so users can understand why an email is suspicious.

## Slide 11: VirusTotal Integration

Content:

- Checks URL reputation.
- Shows malicious/suspicious engine counts.
- Provides report link.
- Falls back gracefully if API key is missing.

Speaker notes:
VirusTotal adds external threat intelligence. The project still works without it by using local analysis.

## Slide 12: Database Design

Content:

Tables:

- `url_scans`
- `email_scans`
- `detection_logs`
- `threat_reports`

Speaker notes:
The database stores all important evidence, including scan results, threat scores, classifications, and timestamps.

## Slide 13: Dashboard

Content:

- Total scans
- Phishing detections
- Active threats
- Average confidence
- Threat timeline chart
- Recent logs

Speaker notes:
The dashboard is designed like a SOC interface for quickly understanding current threat activity.

## Slide 14: Chrome Extension

Content:

- Manifest V3 extension
- Popup active page scanner
- Background service worker
- Website content warning
- Gmail floating scan button

Speaker notes:
The extension brings PhishGuard into the browser, so the user can scan without opening the dashboard manually.

## Slide 15: Gmail Scanner

Content:

- Injects floating button into Gmail.
- Extracts visible sender, subject, and email body.
- Sends content to backend.
- Shows result inside Gmail.

Speaker notes:
This makes email phishing detection practical because users can scan directly from Gmail.

## Slide 16: Example Test Case

Content:

Subject: Important: Verify Your College Account

Indicators found:

- Verification request
- Login URL
- Urgency
- Account restriction threat
- Suspicious domain

Speaker notes:
This test email imitates a common phishing pattern: urgent verification with a suspicious login link.

## Slide 17: Security Features

Content:

- Environment variables for secrets
- Restricted file upload types
- Secure filename handling
- HTML escaping
- API error handling
- Local fallback scanning

Speaker notes:
The project includes defensive coding practices to avoid common web app risks.

## Slide 18: Challenges Faced

Content:

- Gmail button visibility issue
- Extension/backend communication
- Scan timeout handling
- Making error states clear
- Handling optional VirusTotal API key

Speaker notes:
During testing, the Gmail button initially appeared only after opening an email. This was fixed by making it visible on Gmail and showing a helpful message when no email is open.

## Slide 19: Limitations

Content:

- ML model can be improved.
- VirusTotal requires API key.
- Gmail DOM may change.
- Full email headers are needed for stronger authentication analysis.
- Not a replacement for enterprise email security.

Speaker notes:
The project is strong for demonstration and triage, but there is room for production hardening.

## Slide 20: Future Scope

Content:

- Better ML model with larger dataset
- WHOIS/domain age checks
- PDF report export
- User login and roles
- Automatic Gmail link scanning
- Docker deployment
- Admin allowlist/blocklist

Speaker notes:
These improvements would make the project closer to a production cybersecurity tool.

## Slide 21: Conclusion

Content:

- Detects URL and email phishing.
- Provides explainable results.
- Integrates dashboard and browser extension.
- Stores evidence and logs.
- Supports VirusTotal intelligence.
- Useful for cybersecurity awareness and triage.

Speaker notes:
PhishGuard AI successfully combines phishing detection, explainability, and browser-based usability in one project.

## Slide 22: Thank You

Content:

Thank You

Questions?

Speaker notes:
Invite questions about architecture, detection logic, Chrome extension flow, or future improvements.

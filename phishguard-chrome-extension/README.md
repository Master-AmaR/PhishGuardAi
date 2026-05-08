# PhishGuard AI Chrome Extension

Manifest V3 extension that warns when the active website or opened Gmail message looks suspicious.

## Load Locally

1. Start the Flask app so the extension can call `http://127.0.0.1:5000/api/intel/reputation`.
2. Open Chrome and go to `chrome://extensions`.
3. Enable Developer mode.
4. Choose **Load unpacked** and select this `phishguard-chrome-extension` folder.

The extension uses the PhishGuard backend when it is available. If the backend is offline, it falls back to a local URL heuristic and still shows warnings for obvious phishing patterns.

The popup keeps backend details hidden so the result stays simple for normal use.

## Gmail Email Scan

Open a message in Gmail and click **Scan with PhishGuard** in the lower-right corner. The extension sends the visible sender, subject, and message text to the local PhishGuard backend for analysis, then shows the verdict inside Gmail.

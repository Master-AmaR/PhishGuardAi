const GMAIL_SCAN_BUTTON_ID = "phishguard-gmail-scan";
const GMAIL_RESULT_ID = "phishguard-gmail-result";

let scanButton = null;
let resultPanel = null;

initGmailScanner();

function initGmailScanner() {
    ensureGmailControls();
    const observer = new MutationObserver(() => ensureGmailControls());
    observer.observe(document.documentElement, { childList: true, subtree: true });
}

function ensureGmailControls() {
    if (!location.hostname.includes("mail.google.com")) return;

    if (!scanButton) {
        scanButton = document.createElement("button");
        scanButton.id = GMAIL_SCAN_BUTTON_ID;
        scanButton.type = "button";
        scanButton.textContent = "Scan with PhishGuard";
        scanButton.addEventListener("click", scanCurrentEmail);
        document.documentElement.append(scanButton, gmailStyles());
    }
}

async function scanCurrentEmail() {
    const email = collectVisibleEmail();
    if (!email.body || email.body.length < 12) {
        showResult({
            classification: "No email selected",
            severity: "Low",
            threat_score: 0,
            reasons: ["Open an email message before scanning."]
        });
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
    showResult({
        classification: "Scanning email",
        severity: "Low",
        threat_score: 0,
        reasons: ["Checking sender, links, and suspicious language."]
    });

    let result;
    try {
        result = await chrome.runtime.sendMessage({
            type: "phishguard:scan-email",
            email
        });
    } catch (error) {
        result = {
            classification: "Scan unavailable",
            severity: "Low",
            threat_score: 0,
            reasons: [error?.message || "The extension could not contact the scanner."]
        };
    }

    showResult(result);
    scanButton.disabled = false;
    scanButton.textContent = "Scan with PhishGuard";
}

function collectVisibleEmail() {
    const bodyNode = getVisibleEmailBody();
    const subjectNode = document.querySelector("h2[data-thread-perm-id], h2.hP, [data-legacy-thread-id] h2");
    const senderNode = document.querySelector(".gD[email], .go, span[email]");

    return {
        subject: cleanText(subjectNode?.textContent || document.title.replace(/^Gmail\s*-\s*/i, "")),
        sender: senderNode?.getAttribute("email") || cleanText(senderNode?.textContent || ""),
        body: cleanText(bodyNode?.innerText || bodyNode?.textContent || "")
    };
}

function getVisibleEmailBody() {
    const bodies = [...document.querySelectorAll(".a3s.aiL, .a3s")];
    return bodies.reverse().find((node) => {
        const rect = node.getBoundingClientRect();
        return rect.width > 80 && rect.height > 20 && node.innerText.trim().length > 12;
    });
}

function showResult(result) {
    if (!resultPanel) {
        resultPanel = document.createElement("section");
        resultPanel.id = GMAIL_RESULT_ID;
        document.documentElement.append(resultPanel);
    }

    const score = Math.round(result.threat_score || result.ml_confidence || 0);
    const unavailable = result.error || /scan unavailable/i.test(result.classification || "");
    const dangerous = result.severity === "High" || result.severity === "Critical" || score >= 60;
    const careful = !dangerous && (unavailable || score >= 35);
    const title = unavailable ? "Scan unavailable" : dangerous ? "Warning" : careful ? "Be careful" : "Looks safe";
    const reasons = (result.reasons || []).slice(0, 3);

    resultPanel.className = dangerous ? "danger" : careful ? "medium" : "safe";
    resultPanel.innerHTML = `
        <div class="pg-mail-icon">${dangerous ? "!" : careful ? "?" : "OK"}</div>
        <div>
            <strong>${title}: ${escapeHtml(result.classification || "Email scan")}</strong>
            <span>Score ${score}/100</span>
            <ul>${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
        </div>
        <button type="button" aria-label="Close PhishGuard result">Close</button>
    `;
    resultPanel.querySelector("button").addEventListener("click", () => {
        resultPanel.remove();
        resultPanel = null;
    });
}

function removeControls() {
    scanButton?.remove();
    resultPanel?.remove();
    document.getElementById("phishguard-gmail-style")?.remove();
    scanButton = null;
    resultPanel = null;
}

function gmailStyles() {
    if (document.getElementById("phishguard-gmail-style")) {
        return document.createTextNode("");
    }

    const style = document.createElement("style");
    style.id = "phishguard-gmail-style";
    style.textContent = `
        #${GMAIL_SCAN_BUTTON_ID} {
            position: fixed;
            right: 24px;
            bottom: 24px;
            z-index: 2147483647;
            min-height: 42px;
            padding: 0 16px;
            color: #08201d;
            background: #39c5bb;
            border: 0;
            border-radius: 10px;
            box-shadow: 0 14px 36px rgba(0, 0, 0, 0.32);
            font: 700 13px Inter, Segoe UI, Arial, sans-serif;
            cursor: pointer;
        }
        #${GMAIL_SCAN_BUTTON_ID}:disabled {
            cursor: wait;
            opacity: 0.72;
        }
        #${GMAIL_RESULT_ID} {
            position: fixed;
            right: 24px;
            bottom: 78px;
            z-index: 2147483647;
            display: grid;
            grid-template-columns: 44px minmax(0, 1fr) auto;
            gap: 12px;
            align-items: start;
            width: min(480px, calc(100vw - 32px));
            padding: 14px;
            color: #eef2f5;
            background: #15181d;
            border: 1px solid #313841;
            border-radius: 12px;
            box-shadow: 0 18px 48px rgba(0, 0, 0, 0.42);
            font-family: Inter, Segoe UI, Arial, sans-serif;
        }
        #${GMAIL_RESULT_ID}.safe { border-color: rgba(123, 216, 143, 0.55); }
        #${GMAIL_RESULT_ID}.medium { border-color: rgba(240, 179, 90, 0.68); }
        #${GMAIL_RESULT_ID}.danger { border-color: rgba(243, 107, 98, 0.78); }
        #${GMAIL_RESULT_ID} .pg-mail-icon {
            display: grid;
            place-items: center;
            width: 44px;
            height: 44px;
            color: #07120f;
            background: #7bd88f;
            border-radius: 50%;
            font-weight: 900;
        }
        #${GMAIL_RESULT_ID}.medium .pg-mail-icon { background: #f0b35a; }
        #${GMAIL_RESULT_ID}.danger .pg-mail-icon { background: #f36b62; }
        #${GMAIL_RESULT_ID} strong {
            display: block;
            margin-bottom: 3px;
            font-size: 14px;
        }
        #${GMAIL_RESULT_ID} span {
            color: #aab3bc;
            font-size: 12px;
        }
        #${GMAIL_RESULT_ID} ul {
            margin: 8px 0 0;
            padding-left: 17px;
            color: #cbd5dd;
            font-size: 12px;
        }
        #${GMAIL_RESULT_ID} button {
            color: #eef2f5;
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.18);
            border-radius: 8px;
            padding: 7px 9px;
            font: inherit;
            cursor: pointer;
        }
    `;
    return style;
}

function cleanText(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

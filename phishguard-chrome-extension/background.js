const DEFAULT_SETTINGS = {
    backendUrl: "http://127.0.0.1:5000",
    useBackend: true,
    warnThreshold: 55,
    cacheTtlMs: 10 * 60 * 1000,
    requestTimeoutMs: 6000
};

const verdictCache = new Map();
let lastVerdict = null;
const TRUSTED_DOMAINS = [
    "youtube.com",
    "youtu.be",
    "google.com",
    "gmail.com",
    "microsoft.com",
    "office.com",
    "live.com",
    "apple.com",
    "github.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "amazon.com",
    "wikipedia.org"
];

chrome.runtime.onInstalled.addListener(async () => {
    const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
    await chrome.storage.sync.set({ ...DEFAULT_SETTINGS, ...stored });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        analyzeTab(tabId, tab.url);
    }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (tab?.url) analyzeTab(tabId, tab.url);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "phishguard:get-last-verdict") {
        sendResponse(lastVerdict);
        return false;
    }
    if (message?.type === "phishguard:scan-active-tab") {
        scanActiveTab().then(sendResponse).catch((error) => {
            sendResponse(scanErrorVerdict(error));
        });
        return true;
    }
    if (message?.type === "phishguard:scan-email") {
        scanEmail(message.email).then(sendResponse).catch((error) => {
            sendResponse(emailScanError(error));
        });
        return true;
    }
    return false;
});

async function scanActiveTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url) return null;

    return analyzeTab(tab.id, tab.url);
}

async function analyzeTab(tabId, url) {
    if (!isScannableUrl(url)) {
        await setSafeBadge(tabId);
        return null;
    }

    const settings = await chrome.storage.sync.get(DEFAULT_SETTINGS);
    const verdict = await getVerdict(url, settings);
    lastVerdict = verdict;

    await chrome.storage.local.set({ lastVerdict: verdict });
    await chrome.tabs.sendMessage(tabId, { type: "phishguard:verdict", verdict }).catch(() => {});

    if (verdict.shouldWarn) {
        await chrome.action.setBadgeText({ tabId, text: "!" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#f36b62" });
    } else {
        await setSafeBadge(tabId);
    }

    return verdict;
}

async function getVerdict(url, settings) {
    const cacheKey = normalizeCacheKey(url);
    const cached = verdictCache.get(cacheKey);
    if (cached && Date.now() - cached.checkedAt < settings.cacheTtlMs) {
        return cached;
    }

    if (isTrustedDomain(url)) {
        const verdict = trustedDomainVerdict(url);
        verdict.checkedAt = Date.now();
        verdictCache.set(cacheKey, verdict);
        return verdict;
    }

    const local = localHeuristic(url);
    let verdict = local;

    if (settings.useBackend) {
        const backendVerdict = await askBackend(url, settings).catch(() => null);
        if (backendVerdict && shouldPreferBackend(local, backendVerdict)) {
            verdict = backendVerdict;
        }
    }

    verdict.checkedAt = Date.now();
    verdict.shouldWarn = verdict.score >= settings.warnThreshold || verdict.severity === "Critical" || verdict.severity === "High";
    verdictCache.set(cacheKey, verdict);
    return verdict;
}

async function askBackend(url, settings) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), settings.requestTimeoutMs);
    const response = await fetch(`${settings.backendUrl.replace(/\/$/, "")}/api/intel/reputation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: url }),
        signal: controller.signal
    }).finally(() => clearTimeout(timeout));
    if (!response.ok) throw new Error("Backend scan failed");

    const result = await response.json();
    const heuristic = result.heuristic || {};
    const vt = result.virustotal || {};
    const flagged = Number(vt.malicious || 0) + Number(vt.suspicious || 0);
    const score = Math.max(Number(heuristic.threat_score || 0), flagged ? 85 : 0);

    return {
        url,
        source: "PhishGuard backend",
        classification: flagged ? "Known suspicious" : heuristic.classification || "Unknown",
        severity: heuristic.severity || severityFromScore(score),
        score,
        reasons: [
            flagged ? `${flagged} reputation engine flag(s)` : "",
            heuristic.action || "",
            vt.status ? `VirusTotal: ${vt.status}` : ""
        ].filter(Boolean)
    };
}

async function scanEmail(email) {
    const settings = await chrome.storage.sync.get(DEFAULT_SETTINGS);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Math.max(settings.requestTimeoutMs, 25000));
    const formData = new FormData();
    formData.append("content", buildRawEmail(email));

    const response = await fetch(`${settings.backendUrl.replace(/\/$/, "")}/api/scan/email`, {
        method: "POST",
        body: formData,
        signal: controller.signal
    }).finally(() => clearTimeout(timeout));

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(payload.error || "Email scan failed");
    }
    return payload;
}

function buildRawEmail(email = {}) {
    return [
        `From: ${email.sender || "unknown"}`,
        `Subject: ${email.subject || "Gmail message"}`,
        "",
        email.body || ""
    ].join("\n");
}

function shouldPreferBackend(local, backendVerdict) {
    const backendScore = Number(backendVerdict.score || 0);
    const localScore = Number(local.score || 0);

    if (backendScore >= 80 && localScore < 25) {
        return false;
    }
    return backendScore > localScore;
}

function trustedDomainVerdict(url) {
    const parsed = new URL(url);
    return {
        url,
        source: "Trusted domain check",
        classification: "Known legitimate site",
        severity: "Low",
        score: 5,
        shouldWarn: false,
        reasons: [
            `${parsed.hostname} is on the trusted site list`,
            "No strong local phishing indicators"
        ]
    };
}

function isTrustedDomain(url) {
    const host = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    return TRUSTED_DOMAINS.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function scanErrorVerdict(error) {
    return {
        url: "",
        source: "Extension scan",
        classification: "Scan unavailable",
        severity: "Low",
        score: 0,
        shouldWarn: false,
        reasons: [error?.message || "The scan did not finish. Try again in a moment."]
    };
}

function emailScanError(error) {
    const message = error?.name === "AbortError"
        ? "The email scan timed out. Make sure the backend is running and try again."
        : error?.message || "Email scan failed";
    return {
        error: message,
        classification: "Scan unavailable",
        severity: "Low",
        threat_score: 0,
        ml_confidence: 0,
        reasons: [message]
    };
}

function localHeuristic(url) {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    const full = url.toLowerCase();
    const reasons = [];
    let score = 0;

    if (parsed.protocol !== "https:") {
        score += 12;
        reasons.push("Page is not using HTTPS");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        score += 30;
        reasons.push("Host is an IP address");
    }
    if ((host.match(/\./g) || []).length >= 3) {
        score += 12;
        reasons.push("Deep subdomain chain");
    }
    if (full.includes("@") || full.includes("%40")) {
        score += 25;
        reasons.push("URL contains account-like redirect characters");
    }
    if (/(login|verify|secure|account|wallet|bank|payment|update|password|otp|signin)/.test(full)) {
        score += 18;
        reasons.push("Phishing keyword pattern");
    }
    if (/(xn--|bit\.ly|tinyurl|t\.co|rebrand\.ly|is\.gd|cutt\.ly)/.test(full)) {
        score += 18;
        reasons.push("Shortened or encoded host pattern");
    }
    if (full.length > 95) {
        score += 10;
        reasons.push("Long URL structure");
    }

    return {
        url,
        source: "Local extension heuristic",
        classification: score >= 55 ? "Potential phishing" : "No strong phishing signal",
        severity: severityFromScore(score),
        score: Math.min(score, 100),
        reasons: reasons.length ? reasons : ["No strong local phishing indicators"]
    };
}

function severityFromScore(score) {
    if (score >= 80) return "Critical";
    if (score >= 55) return "High";
    if (score >= 35) return "Medium";
    return "Low";
}

function normalizeCacheKey(url) {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.hostname}${parsed.pathname}`;
}

function isScannableUrl(url) {
    return /^https?:\/\//i.test(url || "");
}

async function setSafeBadge(tabId) {
    await chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
}

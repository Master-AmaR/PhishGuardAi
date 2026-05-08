const DEFAULT_SETTINGS = {
    backendUrl: "http://127.0.0.1:5000",
    useBackend: true
};

document.addEventListener("DOMContentLoaded", async () => {
    await chrome.storage.sync.set({
        ...DEFAULT_SETTINGS,
        ...(await chrome.storage.sync.get(DEFAULT_SETTINGS))
    });

    const { lastVerdict } = await chrome.storage.local.get("lastVerdict");
    renderVerdict(lastVerdict);
    scanCurrentPage();

    document.getElementById("scanActiveTab").addEventListener("click", async () => {
        scanCurrentPage();
    });
});

async function scanCurrentPage() {
    const button = document.getElementById("scanActiveTab");
    renderLoading();
    button.disabled = true;
    try {
        const verdict = await withTimeout(
            chrome.runtime.sendMessage({ type: "phishguard:scan-active-tab" }),
            8000
        );
        renderVerdict(verdict);
    } catch (error) {
        renderVerdict({
            classification: "Scan unavailable",
            score: 0,
            shouldWarn: false,
            reasons: ["The scan took too long. Please try again."]
        });
    } finally {
        button.disabled = false;
    }
}

function renderLoading() {
    const box = document.getElementById("verdict");
    box.className = "verdict";
    box.innerHTML = `
        <div class="status-icon">?</div>
        <div>
            <span>Current page</span>
            <strong>Scanning</strong>
            <p>Checking this URL with PhishGuard.</p>
        </div>
    `;
    document.getElementById("reasonCard").hidden = true;
}

function renderVerdict(verdict) {
    const box = document.getElementById("verdict");
    const reasonCard = document.getElementById("reasonCard");
    if (!verdict) {
        reasonCard.hidden = true;
        return;
    }

    const status = getStatus(verdict);
    const reasons = (verdict.reasons || []).slice(0, 3);

    box.className = `verdict ${status.className}`;
    box.innerHTML = `
        <div class="status-icon">${status.icon}</div>
        <div>
            <span>Current page</span>
            <strong>${status.title}</strong>
            <p>${escapeHtml(verdict.classification)} | Score ${Math.round(verdict.score)}/100</p>
        </div>
    `;

    reasonCard.hidden = reasons.length === 0;
    reasonCard.innerHTML = `
        <h2>Why this result?</h2>
        <ul>${reasons.map((reason) => `<li>${escapeHtml(cleanReason(reason))}</li>`).join("")}</ul>
    `;
}

function getStatus(verdict) {
    if (verdict.shouldWarn) {
        return { className: "danger", icon: "!", title: "Warning" };
    }
    if (Number(verdict.score || 0) >= 35) {
        return { className: "medium", icon: "?", title: "Be careful" };
    }
    return { className: "safe", icon: "OK", title: "Looks safe" };
}

function cleanReason(reason) {
    return String(reason).replace(/^ALLOWED\s*[-:]\s*/i, "");
}

function withTimeout(promise, timeoutMs) {
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            setTimeout(() => reject(new Error("Timed out")), timeoutMs);
        })
    ]);
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

let banner = null;

chrome.runtime.onMessage.addListener((message) => {
    if (message?.type !== "phishguard:verdict") return;
    if (isLocalhostPage()) {
        removeWarning();
        return;
    }
    const verdict = message.verdict;
    if (verdict?.shouldWarn) {
        showWarning(verdict);
    } else {
        removeWarning();
    }
});

function showWarning(verdict) {
    if (isLocalhostPage()) return;
    removeWarning();

    banner = document.createElement("div");
    banner.id = "phishguard-warning-banner";
    banner.innerHTML = `
        <div class="pgw-mark">!</div>
        <div class="pgw-copy">
            <strong>PhishGuard AI warning</strong>
            <span>${escapeHtml(verdict.classification)} | Score ${Math.round(verdict.score)}/100</span>
            <small>${escapeHtml((verdict.reasons || []).slice(0, 3).map(cleanReason).join(" | "))}</small>
        </div>
        <button type="button" class="pgw-close" aria-label="Dismiss warning">Dismiss</button>
    `;

    const style = document.createElement("style");
    style.id = "phishguard-warning-style";
    style.textContent = `
        #phishguard-warning-banner {
            position: fixed;
            z-index: 2147483647;
            top: 16px;
            left: 50%;
            display: grid;
            grid-template-columns: 44px minmax(0, 1fr) auto;
            gap: 12px;
            align-items: center;
            width: min(720px, calc(100vw - 28px));
            padding: 14px;
            color: #f8fbfc;
            background: #15181d;
            border: 1px solid rgba(243, 107, 98, 0.72);
            border-radius: 10px;
            box-shadow: 0 18px 48px rgba(0, 0, 0, 0.42);
            font-family: Inter, Segoe UI, Arial, sans-serif;
            transform: translateX(-50%);
        }
        #phishguard-warning-banner .pgw-mark {
            display: grid;
            place-items: center;
            width: 44px;
            height: 44px;
            color: #15181d;
            background: #f36b62;
            border-radius: 50%;
            font-size: 24px;
            font-weight: 900;
        }
        #phishguard-warning-banner .pgw-copy {
            display: grid;
            gap: 3px;
            min-width: 0;
        }
        #phishguard-warning-banner strong,
        #phishguard-warning-banner span,
        #phishguard-warning-banner small {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        #phishguard-warning-banner strong { font-size: 15px; }
        #phishguard-warning-banner span { color: #d8dee4; font-size: 13px; }
        #phishguard-warning-banner small { color: #aab3bc; font-size: 12px; }
        #phishguard-warning-banner .pgw-close {
            padding: 8px 10px;
            color: #f8fbfc;
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.22);
            border-radius: 7px;
            cursor: pointer;
            font: inherit;
        }
        @media (max-width: 620px) {
            #phishguard-warning-banner {
                grid-template-columns: 36px minmax(0, 1fr);
            }
            #phishguard-warning-banner .pgw-mark {
                width: 36px;
                height: 36px;
            }
            #phishguard-warning-banner .pgw-close {
                grid-column: 1 / -1;
            }
        }
    `;

    document.documentElement.append(style, banner);
    banner.querySelector(".pgw-close").addEventListener("click", removeWarning);
}

function removeWarning() {
    banner?.remove();
    document.getElementById("phishguard-warning-style")?.remove();
    banner = null;
}

function cleanReason(reason) {
    return String(reason).replace(/^ALLOWED\s*[-:]\s*/i, "");
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function isLocalhostPage() {
    const host = window.location.hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".localhost");
}

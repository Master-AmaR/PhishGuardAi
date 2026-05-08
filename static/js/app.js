const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => [...root.querySelectorAll(selector)];
let threatChart = null;
let threatTimelineRange = "live";

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function initThreatChart() {
    const canvas = qs("#threatChart");
    if (!canvas || !window.Chart) return;
    const chartData = window.PHISHGUARD_CHART || { labels: ["Now"], values: [0] };
    const context = canvas.getContext("2d");
    const gradient = context.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, "rgba(94,227,216,.48)");
    gradient.addColorStop(1, "rgba(94,227,216,.05)");
    threatChart = new Chart(canvas, {
        type: "line",
        data: {
            labels: chartData.labels,
            datasets: [{
                label: "Threats",
                data: chartData.values,
                fill: true,
                tension: 0.38,
                pointRadius: 4,
                pointHoverRadius: 6,
                pointBackgroundColor: "#5ee3d8",
                pointBorderColor: "#0b1014",
                backgroundColor: gradient,
                borderColor: "rgba(94,227,216,.92)",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { backgroundColor: "#111820", borderColor: "rgba(94,227,216,.3)", borderWidth: 1 } },
            scales: {
                x: { grid: { color: "rgba(94,227,216,.08)" }, ticks: { color: "rgba(238,242,245,.55)" } },
                y: { beginAtZero: true, grid: { color: "rgba(94,227,216,.08)" }, ticks: { color: "rgba(238,242,245,.55)", precision: 0 } }
            }
        }
    });
    bindTimelineControls();
    window.setInterval(() => {
        if (!document.hidden) refreshThreatTimeline();
    }, 5000);
}

async function refreshThreatTimeline() {
    if (!threatChart) return;
    try {
        const response = await fetch(`/api/timeline?range=${encodeURIComponent(threatTimelineRange)}`, {
            headers: { "Accept": "application/json" },
            cache: "no-store"
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Timeline refresh failed");
        const timeline = payload.timeline || { labels: ["Now"], values: [0] };
        threatChart.data.labels = timeline.labels;
        threatChart.data.datasets[0].data = timeline.values;
        threatChart.update("none");
    } catch (error) {
        console.warn(error.message);
    }
}

function bindTimelineControls() {
    qsa("[data-timeline-range]").forEach((button) => {
        button.addEventListener("click", () => {
            threatTimelineRange = button.dataset.timelineRange || "live";
            qsa("[data-timeline-range]").forEach((item) => item.classList.toggle("active", item === button));
            refreshThreatTimeline();
        });
    });
}

function initCounters() {
    qsa("[data-counter]").forEach((node) => {
        const raw = Number(node.dataset.counter);
        if (!Number.isFinite(raw)) return;
        const suffix = node.textContent.trim().endsWith("%") ? "%" : "";
        const formatter = new Intl.NumberFormat();
        const start = performance.now();
        const duration = 820;
        const step = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            const value = raw * eased;
            node.textContent = suffix ? `${value.toFixed(raw % 1 ? 1 : 0)}${suffix}` : formatter.format(Math.round(value));
            if (progress < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    });
}

function bindSidebar() {
    const body = document.body;
    const collapse = qs("[data-sidebar-collapse]");
    const open = qs("[data-sidebar-open]");
    const close = qs("[data-sidebar-close]");

    collapse?.addEventListener("click", () => {
        if (window.matchMedia("(max-width: 720px)").matches) {
            body.classList.remove("sidebar-open");
            return;
        }
        body.classList.toggle("sidebar-collapsed");
        localStorage.setItem("phishguard.sidebarCollapsed", body.classList.contains("sidebar-collapsed") ? "1" : "0");
    });

    open?.addEventListener("click", () => body.classList.add("sidebar-open"));
    close?.addEventListener("click", () => body.classList.remove("sidebar-open"));

    if (localStorage.getItem("phishguard.sidebarCollapsed") === "1") {
        body.classList.add("sidebar-collapsed");
    }
}

async function postJson(url, data) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Request failed");
    return payload;
}

function setFormLoading(form, loading, label = "Scanning") {
    const button = qs("button[type='submit']", form);
    if (!button) return;
    if (loading) {
        button.dataset.originalHtml = button.innerHTML;
        button.disabled = true;
        button.innerHTML = `<span class="button-spinner"></span> ${label}`;
        form.classList.add("is-loading");
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalHtml || button.innerHTML;
        form.classList.remove("is-loading");
    }
}

function bindUrlScanners() {
    qsa("[data-url-scan]").forEach((form) => {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            const url = new FormData(form).get("url");
            const resultBox = qs("#dashboardScanResult") || qs("#urlVerdict");
            try {
                setFormLoading(form, true, "Scanning");
                qsa(".scan-sequence span").forEach((step, index) => {
                    step.classList.toggle("active", index === 0);
                    step.style.animationDelay = `${index * 120}ms`;
                });
                if (resultBox) resultBox.classList.add("loading-surface");
                const result = await postJson("/api/scan/url", { url });
                renderUrlResult(result, resultBox);
            } catch (error) {
                if (resultBox) resultBox.textContent = error.message;
            } finally {
                setFormLoading(form, false);
                if (resultBox) resultBox.classList.remove("loading-surface");
            }
        });
    });
}

function renderUrlResult(result, resultBox) {
    const verdict = qs("#urlVerdict");
    const confidence = qs("#confidenceValue");
    const engines = qs("#enginesFlagged");
    const enginesTotal = qs("#enginesTotal");
    const vtStatusText = qs("#vtStatusText");
    const vtProofLink = qs("#vtProofLink");
    const featureOutput = qs("#featureOutput");
    const consoleBox = qs("#engineConsole");
    const scoreRings = qsa(".ring, .big-ring");
    const indicatorList = qs("#indicatorList");
    const featureCards = qs("#urlFeatureCards");
    const sequenceSteps = qsa(".scan-sequence span");
    result.features = result.features || {};
    const score = Math.round(result.threat_score || result.ml_confidence || 0);
    const confidenceScore = Math.round(result.ml_confidence || 0);
    const keywordHits = result.features.keyword_hits || [];
    const vt = result.virustotal || {};

    if (verdict) {
        verdict.innerHTML = `<span>Analysis Verdict</span><h3>${escapeHtml(result.severity === "Critical" ? "Critical Threat" : result.severity + " Risk")}</h3><p>Classification: ${escapeHtml(result.classification)}. Threat score ${score}/100.</p><em>${escapeHtml(result.action)}</em>`;
    }
    if (confidence) confidence.textContent = `${confidenceScore}%`;
    if (engines) engines.textContent = Number(vt.malicious || 0) + Number(vt.suspicious || 0);
    if (enginesTotal) enginesTotal.textContent = vt.total ? String(vt.total) : vt.detection_ratio === "Pending" ? "Pending" : "0";
    if (vtStatusText) vtStatusText.textContent = vt.status || "VirusTotal status unavailable";
    if (vtProofLink) {
        if (vt.gui_url && (vt.status === "Connected" || vt.status === "Submitted to VirusTotal")) {
            vtProofLink.href = vt.gui_url;
            vtProofLink.classList.remove("disabled");
            vtProofLink.innerHTML = `<i class="bi bi-box-arrow-up-right"></i> Open VirusTotal Report`;
        } else {
            vtProofLink.href = "#";
            vtProofLink.classList.add("disabled");
            vtProofLink.innerHTML = `<i class="bi bi-box-arrow-up-right"></i> VirusTotal Report Unavailable`;
        }
    }
    scoreRings.forEach((ring) => {
        ring.style.setProperty("--score", String(score));
        const value = qs("b", ring);
        if (value && ring.classList.contains("ring")) value.textContent = String(score);
    });
    if (featureOutput) {
        featureOutput.textContent = `URL length: ${result.features.url_length}
HTTPS enabled: ${result.features.https_enabled}
Suspicious characters: ${result.features.suspicious_characters}
Redirect markers: ${result.features.redirect_markers}
IP-based URL: ${result.features.ip_based_url}
Domain: ${result.features.domain}
Subdomain depth: ${result.features.subdomain_depth}
Keyword hits: ${keywordHits.join(", ") || "none"}`;
    }
    if (indicatorList) {
        indicatorList.innerHTML = `<div><i class="bi bi-link-45deg"></i><strong>Structure Score</strong><span>${escapeHtml(result.features.url_length)} characters, ${escapeHtml(result.features.suspicious_characters)} suspicious symbols, ${escapeHtml(result.features.redirect_markers)} redirect markers</span><em>${score >= 55 ? "Elevated" : "Normal"}</em></div>
<div><i class="bi bi-globe2"></i><strong>Domain Signals</strong><span>${escapeHtml(result.features.domain || "unknown")} with depth ${escapeHtml(result.features.subdomain_depth)}</span><em>${result.features.ip_based_url ? "IP Host" : "Domain"}</em></div>
<div><i class="bi bi-key"></i><strong>Keyword Matches</strong><span>${escapeHtml(keywordHits.join(", ") || "No suspicious terms found")}</span><em>${keywordHits.length ? "Matched" : "Clear"}</em></div>`;
    }
    if (featureCards) {
        featureCards.innerHTML = `<article><span>HTTPS</span><strong>${result.features.https_enabled ? "Enabled" : "Missing"}</strong><small>Transport security</small></article>
<article><span>Domain Age</span><strong>Enrichment</strong><small>Not in local model</small></article>
<article><span>Symbols</span><strong>${escapeHtml(result.features.suspicious_characters ?? 0)}</strong><small>Suspicious characters</small></article>
<article><span>Redirects</span><strong>${escapeHtml(result.features.redirect_markers ?? 0)}</strong><small>Redirect markers</small></article>
<article><span>IP Host</span><strong>${result.features.ip_based_url ? "Detected" : "No"}</strong><small>IP-based URL detection</small></article>
<article><span>Depth</span><strong>${escapeHtml(result.features.subdomain_depth ?? 0)}</strong><small>Subdomain depth</small></article>`;
    }
    sequenceSteps.forEach((step) => step.classList.add("active"));
    if (consoleBox) {
        consoleBox.innerHTML = `<strong>Engine Console</strong>
<p>&gt; Normalized target: ${escapeHtml(result.target)}</p>
<p>&gt; Extracted domain features and redirect markers.</p>
<p>&gt; VirusTotal: ${escapeHtml(vt.status || "Unavailable")} (${escapeHtml(vt.detection_ratio || "n/a")})</p>
<p class="warning">&gt; Verdict: ${escapeHtml(result.classification)} (${confidenceScore}%)</p>
<p>&gt; Action: ${escapeHtml(result.action)}</p>`;
    }
    if (resultBox && !verdict) {
        resultBox.textContent = `Verdict: ${result.classification} - Confidence ${confidenceScore}% - ${result.action}`;
    }
    refreshThreatTimeline();
}

function bindEmailScanner() {
    const form = qs("[data-email-scan]");
    if (!form) return;
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const resultBox = qs("#emailResult");
        try {
            setFormLoading(form, true, "Analyzing");
            resultBox?.classList.add("loading-surface");
            const response = await fetch("/api/scan/email", { method: "POST", body: new FormData(form) });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || "Analysis failed");
            renderEmailResult(result, resultBox);
        } catch (error) {
            resultBox.textContent = error.message;
        } finally {
            setFormLoading(form, false);
            resultBox?.classList.remove("loading-surface");
        }
    });
}

function renderEmailResult(result, resultBox) {
    result.extracted_urls = result.extracted_urls || [];
    result.suspicious_terms = result.suspicious_terms || [];
    result.unique_domains = result.unique_domains || [];
    result.reasons = result.reasons || [];
    const reputationRows = (result.url_reputation || []).map((entry) => {
        const vt = entry.virustotal || {};
        const flagged = Number(vt.malicious || 0) + Number(vt.suspicious || 0);
        const total = vt.total || 0;
        const proof = vt.gui_url
            ? `<a class="outline-action" href="${escapeHtml(vt.gui_url)}" target="_blank" rel="noopener"><i class="bi bi-box-arrow-up-right"></i> VirusTotal</a>`
            : `<span class="muted-label">No report link</span>`;
        return `<article class="url-evidence">
            <div><strong>${escapeHtml(entry.url)}</strong><span>${escapeHtml(vt.status || "Unavailable")} · ${escapeHtml(vt.detection_ratio || `${flagged}/${total}`)}</span></div>
            ${proof}
        </article>`;
    }).join("");
    const hiddenCount = result.url_reputation_truncated
        ? `<p class="muted-label">${result.url_reputation_truncated} additional URL(s) were extracted but not checked to conserve quota.</p>`
        : "";

    const score = Math.round(result.ml_confidence || result.threat_score || 0);
    resultBox.innerHTML = `<div class="email-verdict ${result.severity?.toLowerCase() || "low"}">
        <span>Verdict</span>
        <strong>${escapeHtml(result.classification)}</strong>
        <em>${score}% triage confidence</em>
        <div class="meter ${score >= 75 ? "danger" : score >= 60 ? "warn" : "safe"}"><i style="width: ${score}%"></i></div>
    </div>
    <div class="meta-grid">
        <div><span>From</span><strong>${escapeHtml(result.sender)}</strong></div>
        <div><span>Subject</span><strong>${escapeHtml(result.subject)}</strong></div>
        <div><span>Reply-To</span><strong>${escapeHtml(result.reply_to)}</strong></div>
        <div><span>Sender IP</span><strong>${escapeHtml(result.sender_ip || "not provided")}</strong></div>
        <div><span>URLs</span><strong>${escapeHtml(result.extracted_urls.length)}</strong></div>
        <div><span>Evidence Domains</span><strong>${escapeHtml((result.unique_evidence_domains || []).length || 0)}</strong></div>
    </div>
    <h4>Why This Verdict</h4>
    <ul class="reason-list">${result.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
    <h4>Extracted URL Reputation</h4>
    <div class="url-evidence-list">${reputationRows || `<div class="empty-state">No URLs were extracted from this email.</div>`}</div>
    ${hiddenCount}
    <h4>Local Indicators</h4>
    <p>Suspicious terms: ${result.suspicious_terms.map((term) => `<mark>${escapeHtml(term)}</mark>`).join(" ") || "None"}</p>
    <p>Unique domains: ${escapeHtml(result.unique_domains.join(", ") || "None")}</p>`;
    refreshThreatTimeline();
}

function bindLogSearch() {
    const input = qs("#logSearch");
    const table = qs("#logsTable");
    if (!table) return;
    const filterButtons = qsa("[data-log-filters] [data-filter]");
    const countLabel = qs("#logCountLabel");
    let severityFilter = "all";

    const applyFilters = () => {
        const needle = (input?.value || "").toLowerCase();
        let visible = 0;
        qsa("[data-log-row]", table).forEach((row) => {
            const detail = row.nextElementSibling?.matches("[data-log-detail]") ? row.nextElementSibling : null;
            const matchesSearch = row.textContent.toLowerCase().includes(needle);
            const matchesSeverity = severityFilter === "all" || row.dataset.severity === severityFilter;
            const show = matchesSearch && matchesSeverity;
            row.style.display = show ? "" : "none";
            if (detail && !row.classList.contains("expanded")) detail.style.display = "none";
            if (detail && !show) detail.style.display = "none";
            if (show) visible += 1;
        });
        if (countLabel) countLabel.textContent = `Showing ${visible} entr${visible === 1 ? "y" : "ies"}`;
    };

    input?.addEventListener("input", applyFilters);
    filterButtons.forEach((button) => {
        button.addEventListener("click", () => {
            filterButtons.forEach((item) => item.classList.remove("active"));
            button.classList.add("active");
            severityFilter = button.dataset.filter;
            applyFilters();
        });
    });

    qsa("[data-expand-log]", table).forEach((button) => {
        button.addEventListener("click", () => {
            const row = button.closest("[data-log-row]");
            const detail = row?.nextElementSibling?.matches("[data-log-detail]") ? row.nextElementSibling : null;
            if (!row || !detail) return;
            const expanded = row.classList.toggle("expanded");
            detail.style.display = expanded ? "table-row" : "none";
            button.innerHTML = expanded ? `<i class="bi bi-chevron-down"></i>` : `<i class="bi bi-chevron-right"></i>`;
        });
    });

    applyFilters();
}

document.addEventListener("DOMContentLoaded", () => {
    bindSidebar();
    initThreatChart();
    initCounters();
    bindUrlScanners();
    bindEmailScanner();
    bindLogSearch();
});

import ipaddress
import hashlib
import re
from html import unescape
from email import policy
from email.parser import Parser
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import joblib
from flask import current_app, has_app_context

from database.db import get_db


SUSPICIOUS_TERMS = {
    "account",
    "banco",
    "bradesco",
    "cartao",
    "cartão",
    "clique aqui",
    "cliente",
    "expirando",
    "verify",
    "urgent",
    "hoje",
    "livelo",
    "pontos",
    "password",
    "suspended",
    "restricted",
    "login",
    "update",
    "wallet",
    "invoice",
    "security alert",
}

BRAND_TERMS = {
    "bradesco": ["bradesco"],
    "livelo": ["livelo"],
}

URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}


RESOURCE_DOMAINS = {
    "fonts.googleapis.com",
    "fonts.gstatic.com",
}


TRUSTED_SHOPPING_DOMAINS = {
    "amazon.com",
    "amazon.in",
    "ebay.com",
    "flipkart.com",
    "myntra.com",
    "snapdeal.com",
}


TRACKING_PARAMS = {
    "_encoding",
    "affid",
    "bu",
    "cid",
    "content-id",
    "dc",
    "dib",
    "dib_tag",
    "ds",
    "fm",
    "i",
    "iid",
    "lid",
    "marketplace",
    "otracker",
    "ov_redirect",
    "pd_rd_r",
    "pd_rd_w",
    "pd_rd_wg",
    "pf_rd_p",
    "pf_rd_r",
    "pid",
    "ppt",
    "ppn",
    "qid",
    "ref",
    "refinements",
    "restrictlocale",
    "rh",
    "rnid",
    "s",
    "sid",
    "srno",
    "sr",
    "store",
    "tag",
    "th",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
}

URL_MODEL_CACHE = {"path": None, "model": None}


def is_domain_match(host, domain):
    return host == domain or host.endswith(f".{domain}")


def is_trusted_shopping_domain(host):
    return any(is_domain_match(host, domain) for domain in TRUSTED_SHOPPING_DOMAINS)


def known_marketplace_pattern(host, path):
    if is_domain_match(host, "flipkart.com"):
        return bool(re.search(r"/p/itm[a-z0-9]+", path)) or path.startswith("/all/")
    if is_domain_match(host, "amazon.in") or is_domain_match(host, "amazon.com"):
        return bool(re.search(r"/dp/[a-z0-9]{10}", path)) or path == "/s"
    return False


def extract_url_features(target_url):
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    host = (parsed.hostname or parsed.netloc).lower()
    path = parsed.path.lower()
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    query_param_names = [name.lower() for name, _ in query_params]
    tracking_param_count = sum(1 for name in query_param_names if name in TRACKING_PARAMS)
    structural_target = f"{parsed.netloc}{parsed.path}"
    is_ip = False
    try:
        ipaddress.ip_address(host.split(":")[0])
        is_ip = True
    except ValueError:
        pass

    return {
        "url_length": len(target_url),
        "https_enabled": parsed.scheme == "https",
        "suspicious_characters": sum(structural_target.count(char) for char in ["@", "-", "_", "%"]),
        "query_param_count": len(query_params),
        "tracking_param_count": tracking_param_count,
        "redirect_markers": sum(1 for name in query_param_names if name in {"url", "u", "redirect", "redirect_url", "return", "return_url", "next"}),
        "ip_based_url": is_ip,
        "domain": host,
        "subdomain_depth": max(host.count(".") - 1, 0),
        "trusted_shopping_domain": is_trusted_shopping_domain(host),
        "known_marketplace_pattern": known_marketplace_pattern(host, path),
        "keyword_hits": [term for term in SUSPICIOUS_TERMS if term in f"{host}{path}"],
    }


def url_model_features(features):
    query_param_count = features["query_param_count"] or 0
    return {
        "url_length": features["url_length"],
        "https_enabled": int(features["https_enabled"]),
        "suspicious_characters": features["suspicious_characters"],
        "query_param_count": query_param_count,
        "tracking_ratio": features["tracking_param_count"] / max(query_param_count, 1),
        "redirect_markers": features["redirect_markers"],
        "ip_based_url": int(features["ip_based_url"]),
        "subdomain_depth": features["subdomain_depth"],
        "trusted_shopping_domain": int(features["trusted_shopping_domain"]),
        "known_marketplace_pattern": int(features["known_marketplace_pattern"]),
        "keyword_count": len(features["keyword_hits"]),
    }


def load_url_model():
    if not has_app_context():
        return None
    model_path = Path(current_app.config.get("ML_MODEL_PATH", ""))
    if URL_MODEL_CACHE["path"] == model_path:
        return URL_MODEL_CACHE["model"]
    URL_MODEL_CACHE["path"] = model_path
    URL_MODEL_CACHE["model"] = joblib.load(model_path) if model_path.exists() else None
    return URL_MODEL_CACHE["model"]


def url_indicators(features, score):
    indicators = []
    if not features["https_enabled"]:
        indicators.append("Missing HTTPS increases interception and impersonation risk.")
    if features["ip_based_url"]:
        indicators.append("The host is an IP address instead of a recognizable domain.")
    if features["suspicious_characters"]:
        indicators.append(f"URL structure contains {features['suspicious_characters']} suspicious symbol(s).")
    if features["redirect_markers"]:
        indicators.append(f"Query string contains {features['redirect_markers']} redirect marker(s).")
    if features["subdomain_depth"] >= 2:
        indicators.append(f"Domain has deep subdomain nesting: depth {features['subdomain_depth']}.")
    if features["keyword_hits"]:
        indicators.append(f"Phishing keyword matches found: {', '.join(features['keyword_hits'])}.")
    if features["trusted_shopping_domain"] and features["known_marketplace_pattern"]:
        indicators.append("Trusted marketplace URL pattern reduced the risk score.")
    if not indicators:
        indicators.append("No strong local phishing indicators were found.")
    indicators.append(f"Final URL threat score is {score}/100.")
    return indicators


def url_pattern_profile(features):
    return {
        "domain": features.get("domain"),
        "https_enabled": features.get("https_enabled"),
        "ip_based_url": features.get("ip_based_url"),
        "subdomain_depth": features.get("subdomain_depth"),
        "keyword_hits": features.get("keyword_hits", []),
        "redirect_markers": features.get("redirect_markers"),
        "known_marketplace_pattern": features.get("known_marketplace_pattern"),
    }


def predict_url(target_url):
    features = extract_url_features(target_url)
    model = load_url_model()
    model_confidence = None
    model_label = None
    score = 8
    score += min(features["url_length"] // 16, 12)
    score += 12 if not features["https_enabled"] else 0
    score += min(features["suspicious_characters"] * 4, 20)
    score += min(max(features["query_param_count"] - features["tracking_param_count"], 0) * 2, 10)
    score += min(features["redirect_markers"] * 8, 20)
    score += 18 if features["ip_based_url"] else 0
    score += min(features["subdomain_depth"] * 7, 14)
    score += min(len(features["keyword_hits"]) * 8, 24)
    if model is not None:
        model_input = [url_model_features(features)]
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(model_input)[0]
            model_label_index = list(model.classes_).index("legit")
            model_confidence = round(float(probabilities[model_label_index]) * 100, 1)
        model_label = str(model.predict(model_input)[0])

    if features["trusted_shopping_domain"] and features["https_enabled"] and not features["ip_based_url"]:
        score -= 18
        if features["known_marketplace_pattern"] and features["tracking_param_count"] >= 2:
            score -= 8
        if not features["keyword_hits"] and features["redirect_markers"] <= 1:
            score = min(score, 32)
        if model_label == "legit" and model_confidence and model_confidence >= 70:
            score = min(score, 28)
    elif model_label == "suspicious" and model_confidence and model_confidence < 35:
        score += 10
    score = min(score, 99)
    score = max(score, 0)

    if score >= 80:
        classification = "Credential Harvesting Phishing"
        severity = "Critical"
        action = "BLOCKED"
    elif score >= 55:
        classification = "Suspicious Phishing"
        severity = "High"
        action = "QUARANTINED"
    elif score >= 35:
        classification = "Potentially Suspicious"
        severity = "Medium"
        action = "LOGGED"
    else:
        classification = "Benign"
        severity = "Low"
        action = "ALLOWED"

    return {
        "target": target_url,
        "classification": classification,
        "threat_score": score,
        "ml_confidence": min(score + 4, 99),
        "severity": severity,
        "action": action,
        "summary": (
            f"{classification} verdict for {target_url}: severity {severity}, "
            f"score {score}/100, action {action}."
        ),
        "important_indicators": url_indicators(features, score),
        "pattern_profile": url_pattern_profile(features),
        "features": features,
        "model_label": model_label,
        "model_confidence": model_confidence,
    }


def decoded_email_text(parsed_email, raw_content):
    parts = []
    try:
        if parsed_email.is_multipart():
            for part in parsed_email.walk():
                if part.get_content_maintype() == "text":
                    parts.append(part.get_content())
        else:
            parts.append(parsed_email.get_content())
    except Exception:
        parts.append(raw_content)
    return unescape("\n".join(part for part in parts if part))


def extract_urls_from_text(text):
    urls = re.findall(r"https?://[^\s<>'\")]+", text)
    cleaned = []
    for url in urls:
        cleaned.append(url.rstrip(".,;:]}"))
    return cleaned


def email_pattern_key(terms, unique_evidence_domains, shortened_urls, reply_to_mismatch, auth_weak, auth_failed, url_count):
    profile_parts = [
        f"terms:{','.join(sorted(terms))}",
        f"domains:{min(len(unique_evidence_domains), 4)}",
        f"shorteners:{min(len(shortened_urls), 2)}",
        f"reply:{int(reply_to_mismatch)}",
        f"authweak:{int(auth_weak)}",
        f"authfail:{int(auth_failed)}",
        f"urls:{min(url_count, 5)}",
    ]
    raw = "|".join(profile_parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20], raw


def learned_email_pattern_signal(pattern_key):
    if not has_app_context():
        return None
    try:
        row = get_db().execute(
            """
            SELECT pattern_label, severity, observation_count, confidence_total
            FROM learned_email_patterns
            WHERE pattern_key = ?
            """,
            (pattern_key,),
        ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    return dict(row)


def analyze_email_content(content):
    parsed_email = Parser(policy=policy.default).parsestr(content)
    sender = (parsed_email.get("from") or "").strip()
    subject = (parsed_email.get("subject") or "").strip()
    reply_to = (parsed_email.get("reply-to") or "").strip()
    authentication_results = (parsed_email.get("authentication-results") or "").strip()
    antispam = (parsed_email.get("x-microsoft-antispam") or "").strip()
    sender_ip = (parsed_email.get("x-sender-ip") or "").strip()
    scl = (parsed_email.get("x-ms-exchange-organization-scl") or "").strip()
    decoded_text = decoded_email_text(parsed_email, content)
    evidence_text = f"{subject}\n{sender}\n{decoded_text}"
    lower = evidence_text.lower()
    urls = extract_urls_from_text(decoded_text)
    terms = [term for term in SUSPICIOUS_TERMS if term in lower]

    domains = []
    shortened_urls = []
    evidence_urls = []
    for url in urls:
        host = urlparse(url).netloc.lower()
        if host:
            domains.append(host)
        if host and host not in RESOURCE_DOMAINS:
            evidence_urls.append(url)
        if host in URL_SHORTENERS:
            shortened_urls.append(url)

    unique_domains = sorted(set(domains))
    unique_evidence_domains = sorted({urlparse(url).netloc.lower() for url in evidence_urls if urlparse(url).netloc})
    reply_to_mismatch = bool(reply_to and sender and reply_to.lower() != sender.lower())
    auth_failed = bool(authentication_results and any(marker in authentication_results.lower() for marker in ["spf=fail", "dkim=fail", "dmarc=fail"]))
    auth_weak = bool(authentication_results and any(marker in authentication_results.lower() for marker in ["spf=temperror", "dmarc=temperror", "dkim=none", "compauth=fail"]))
    pattern_key, pattern_raw = email_pattern_key(
        terms,
        unique_evidence_domains,
        shortened_urls,
        reply_to_mismatch,
        auth_weak,
        auth_failed,
        len(urls),
    )
    learned_signal = learned_email_pattern_signal(pattern_key)
    reasons = []
    if urls:
        reasons.append(f"Contains {len(urls)} embedded URL{'s' if len(urls) != 1 else ''}.")
    if len(unique_evidence_domains) >= 2:
        reasons.append(f"Actionable links span {len(unique_evidence_domains)} unique domains.")
    if shortened_urls:
        reasons.append(f"Uses {len(shortened_urls)} URL shortener{'s' if len(shortened_urls) != 1 else ''}.")
    if terms:
        reasons.append(f"Suspicious language matched: {', '.join(terms)}.")
    if reply_to_mismatch:
        reasons.append("Reply-To differs from From header.")
    if auth_failed:
        reasons.append("Authentication headers contain SPF, DKIM, or DMARC failure.")
    if auth_weak:
        reasons.append("Authentication results are weak or failed, including SPF/DMARC temp error, DKIM none, or composite auth failure.")
    if sender_ip:
        reasons.append(f"Message arrived from sender IP {sender_ip}.")
    if scl.isdigit() and int(scl) >= 5:
        reasons.append(f"Microsoft spam confidence level is elevated: SCL {scl}.")
    if "bcl:" in antispam.lower():
        match = re.search(r"bcl:(\d+)", antispam, re.IGNORECASE)
        if match and int(match.group(1)) >= 7:
            reasons.append(f"Bulk complaint level is high: BCL {match.group(1)}.")

    trusted_matches = []
    mentioned_brands = [brand for brand, keywords in BRAND_TERMS.items() if any(keyword in lower for keyword in keywords)]
    if mentioned_brands and unique_evidence_domains:
        trusted_matches = [
            domain
            for domain in unique_evidence_domains
            if any(brand in domain for brand in mentioned_brands)
        ]
        if not trusted_matches:
            reasons.append(f"Message impersonates {', '.join(mentioned_brands)} but links to unrelated domain(s): {', '.join(unique_evidence_domains[:3])}.")
    if not reasons:
        reasons.append("No strong phishing indicators were found by local triage rules.")

    score = 18
    score += min(len(urls) * 7, 35)
    score += min(len(unique_evidence_domains) * 5, 20)
    score += min(len(shortened_urls) * 12, 24)
    score += min(len(terms) * 10, 24)
    score += 10 if reply_to_mismatch else 0
    score += 14 if auth_failed else 0
    score += 18 if authentication_results and "compauth=fail" in authentication_results.lower() else 0
    score += 8 if authentication_results and "dkim=none" in authentication_results.lower() else 0
    score += 8 if authentication_results and ("spf=temperror" in authentication_results.lower() or "dmarc=temperror" in authentication_results.lower()) else 0
    score += 10 if scl.isdigit() and int(scl) >= 5 else 0
    score += 10 if mentioned_brands and unique_evidence_domains and not trusted_matches else 0
    if learned_signal and learned_signal["observation_count"] >= 2:
        learned_label = learned_signal["pattern_label"]
        if learned_label != "Benign":
            score += min(learned_signal["observation_count"] * 3, 12)
            reasons.append(
                f"Similar email pattern was seen {learned_signal['observation_count']} time(s) before and previously classified as {learned_label}."
            )
        else:
            score -= min(learned_signal["observation_count"] * 2, 8)
            reasons.append(
                f"Similar email pattern was seen {learned_signal['observation_count']} time(s) before and previously classified as benign."
            )
    score = min(score, 98)
    score = max(score, 0)

    classification = "Email Phishing" if score >= 60 else "Benign"
    severity = "High" if score >= 75 else "Medium" if score >= 60 else "Low"
    action = "QUARANTINED" if score >= 60 else "ALLOWED"

    return {
        "sender": sender or "unknown",
        "subject": subject or "Inline analysis",
        "reply_to": reply_to or "not provided",
        "authentication_results": authentication_results or "not provided",
        "sender_ip": sender_ip or "not provided",
        "classification": classification,
        "threat_score": score,
        "ml_confidence": min(score + 3, 99),
        "severity": severity,
        "action": action,
        "suspicious_terms": terms,
        "extracted_urls": urls,
        "evidence_urls": evidence_urls,
        "unique_domains": unique_domains,
        "unique_evidence_domains": unique_evidence_domains,
        "shortened_urls": shortened_urls,
        "reasons": reasons,
        "summary": (
            f"{classification} verdict for email from {sender or 'unknown'} with subject "
            f"'{subject or 'Inline analysis'}': severity {severity}, score {score}/100, action {action}."
        ),
        "important_indicators": reasons,
        "pattern_profile": {
            "pattern_key": pattern_key,
            "signature": pattern_raw,
            "url_count": len(urls),
            "evidence_domain_count": len(unique_evidence_domains),
            "shortener_count": len(shortened_urls),
            "reply_to_mismatch": reply_to_mismatch,
            "auth_failed": auth_failed,
            "auth_weak": auth_weak,
            "suspicious_terms": terms,
            "learned_observations": learned_signal["observation_count"] if learned_signal else 0,
            "learned_label": learned_signal["pattern_label"] if learned_signal else "new pattern",
        },
    }

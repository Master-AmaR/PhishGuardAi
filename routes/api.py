from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from models.repositories import create_email_scan, create_url_scan, dashboard_metrics, list_recent_logs, severity_counts, threat_timeline
from services.ml_service import analyze_email_content, predict_url
from services.virustotal_service import VirusTotalService
from utils.validators import allowed_file, is_valid_url


api_bp = Blueprint("api", __name__)


@api_bp.get("/metrics")
def metrics():
    return jsonify({"metrics": dashboard_metrics()})


@api_bp.get("/timeline")
def timeline():
    window = request.args.get("range", "live")
    if window not in {"live", "24h", "7d"}:
        window = "live"
    return jsonify({"timeline": threat_timeline(window)})


@api_bp.get("/logs/recent")
def recent_logs():
    logs = [dict(row) for row in list_recent_logs(10)]
    return jsonify({"logs": logs})


@api_bp.get("/reports/snapshot")
def report_snapshot():
    logs = [dict(row) for row in list_recent_logs(25)]
    return jsonify(
        {
            "metrics": dashboard_metrics(),
            "severity_counts": severity_counts(),
            "logs": logs,
            "generated_at": logs[0]["created_at"] if logs else "No evidence yet",
        }
    )


@api_bp.post("/scan/url")
def scan_url():
    payload = request.get_json(silent=True) or request.form
    target_url = (payload.get("url") or "").strip()
    if not is_valid_url(target_url):
        return jsonify({"error": "A valid URL or domain is required."}), 400

    result = predict_url(target_url)
    vt_result = VirusTotalService().reputation_lookup(target_url)
    result["virustotal"] = vt_result
    result["vt_detection_ratio"] = vt_result["detection_ratio"]
    create_url_scan(result)
    return jsonify(result)


@api_bp.post("/scan/email")
def scan_email():
    content = request.form.get("content", "")
    upload = request.files.get("email_file")

    if upload and upload.filename:
        if not allowed_file(upload.filename, current_app.config["ALLOWED_EMAIL_EXTENSIONS"]):
            return jsonify({"error": "Only .eml and .txt files are accepted."}), 400
        filename = secure_filename(upload.filename)
        file_bytes = upload.read(current_app.config["MAX_CONTENT_LENGTH"])
        content = file_bytes.decode("utf-8", errors="ignore")
        result_source = filename
    else:
        result_source = "inline-email"

    if len(content.strip()) < 12:
        return jsonify({"error": "Email content is too short for analysis."}), 400

    result = analyze_email_content(content)
    result["source"] = result_source
    vt = VirusTotalService()
    reputation_targets = result.get("evidence_urls") or result.get("extracted_urls", [])
    result["url_reputation"] = [
        {"url": url, "virustotal": vt.reputation_lookup(url)}
        for url in reputation_targets[:5]
    ]
    result["url_reputation_truncated"] = max(len(reputation_targets) - 5, 0)
    create_email_scan(result)
    return jsonify(result)


@api_bp.post("/intel/reputation")
def intel_reputation():
    payload = request.get_json(silent=True) or request.form
    target = (payload.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target is required."}), 400

    ml_result = predict_url(target)
    vt_result = VirusTotalService().reputation_lookup(target)
    return jsonify({"target": target, "heuristic": ml_result, "virustotal": vt_result})

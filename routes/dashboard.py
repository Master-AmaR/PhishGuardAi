import csv
import io

from flask import Blueprint, Response, current_app, render_template

from models.repositories import dashboard_metrics, list_active_threats, list_all_logs, list_recent_logs, severity_counts, threat_timeline
from services.virustotal_service import VirusTotalService


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def dashboard():
    vt = VirusTotalService()
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        metrics=dashboard_metrics(),
        logs=list_recent_logs(5),
        active_threats=list_active_threats(3),
        severity_counts=severity_counts(),
        timeline=threat_timeline(),
        vt_status="Connected" if vt.enabled else "Standby",
    )


@dashboard_bp.route("/url-scanner")
def url_scanner():
    return render_template("url_scanner.html", active_page="url_scanner")


@dashboard_bp.route("/email-analyzer")
def email_analyzer():
    return render_template("email_analyzer.html", active_page="email_analyzer")


@dashboard_bp.route("/logs")
def logs():
    return render_template("logs.html", active_page="logs", logs=list_all_logs())


@dashboard_bp.route("/reports")
def reports():
    return render_template("reports.html", active_page="reports", logs=list_recent_logs(8))


@dashboard_bp.route("/logs/export.csv")
def export_logs_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp UTC",
        "Target / Source",
        "Severity",
        "Threat Type",
        "Confidence",
        "Scan Source",
        "Action Taken",
        "Summary",
        "Important Indicators",
    ])
    for row in list_all_logs():
        writer.writerow(
            [
                row["created_at"],
                row["target_source"],
                row["severity"],
                row["threat_type"],
                row["ai_confidence"],
                row["scan_source"],
                row["action_taken"],
                row["summary_text"],
                " | ".join(row.get("indicators", [])),
            ]
        )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_detection_logs.csv"},
    )


@dashboard_bp.app_context_processor
def inject_app_meta():
    return {"app_version": "v.2.4.0", "app_name": current_app.name}

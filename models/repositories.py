import json

from database.db import get_db


def create_url_scan(result):
    db = get_db()
    db.execute(
        """
        INSERT INTO url_scans
        (target_url, classification, threat_score, ml_confidence, vt_detection_ratio, features_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            result["target"],
            result["classification"],
            result["threat_score"],
            result["ml_confidence"],
            result.get("vt_detection_ratio", "0/90"),
            json.dumps(result.get("features", {})),
        ),
    )
    create_detection_log(
        target_source=result["target"],
        severity=result["severity"],
        threat_type=result["classification"],
        ai_confidence=result["ml_confidence"],
        scan_source="URL Scanner",
        action_taken=result["action"],
        commit=False,
    )
    db.commit()


def create_email_scan(result):
    db = get_db()
    db.execute(
        """
        INSERT INTO email_scans
        (sender, subject, extracted_urls, classification, threat_score, ml_confidence, suspicious_terms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.get("sender", "unknown"),
            result.get("subject", "No subject"),
            json.dumps(result.get("extracted_urls", [])),
            result["classification"],
            result["threat_score"],
            result["ml_confidence"],
            json.dumps(result.get("suspicious_terms", [])),
        ),
    )
    create_detection_log(
        target_source=result.get("sender", "Email body"),
        severity=result["severity"],
        threat_type=result["classification"],
        ai_confidence=result["ml_confidence"],
        scan_source="Email Analyzer",
        action_taken=result["action"],
        commit=False,
    )
    db.commit()


def create_detection_log(target_source, severity, threat_type, ai_confidence, scan_source, action_taken, commit=True):
    db = get_db()
    db.execute(
        """
        INSERT INTO detection_logs
        (target_source, severity, threat_type, ai_confidence, scan_source, action_taken)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (target_source, severity, threat_type, ai_confidence, scan_source, action_taken),
    )
    if commit:
        db.commit()


def list_recent_logs(limit=8):
    return get_db().execute(
        "SELECT * FROM detection_logs ORDER BY created_at DESC, id DESC LIMIT ?",
        (limit,),
    ).fetchall()


def list_all_logs():
    return get_db().execute(
        "SELECT * FROM detection_logs ORDER BY created_at DESC, id DESC"
    ).fetchall()


def dashboard_metrics():
    db = get_db()
    total_url = db.execute("SELECT COUNT(*) AS count FROM url_scans").fetchone()["count"]
    total_email = db.execute("SELECT COUNT(*) AS count FROM email_scans").fetchone()["count"]
    phishing = db.execute(
        "SELECT COUNT(*) AS count FROM detection_logs WHERE threat_type != 'Benign'"
    ).fetchone()["count"]
    critical = db.execute(
        "SELECT COUNT(*) AS count FROM detection_logs WHERE severity IN ('Critical', 'High')"
    ).fetchone()["count"]
    avg_confidence = db.execute(
        "SELECT AVG(ai_confidence) AS average FROM detection_logs"
    ).fetchone()["average"]
    return {
        "total_scans": total_url + total_email,
        "phishing_detections": phishing,
        "active_threats": critical,
        "ml_accuracy": round(avg_confidence or 0, 1),
    }


def severity_counts():
    db = get_db()
    rows = db.execute(
        """
        SELECT severity, COUNT(*) AS count
        FROM detection_logs
        GROUP BY severity
        """
    ).fetchall()
    return {row["severity"]: row["count"] for row in rows}


def threat_timeline(window="live"):
    if window == "7d":
        label_expr = "strftime('%m/%d', created_at)"
        since_clause = "WHERE datetime(created_at) >= datetime('now', '-7 days')"
        limit = 7
    elif window == "24h":
        label_expr = "strftime('%H:00', created_at)"
        since_clause = "WHERE datetime(created_at) >= datetime('now', '-24 hours')"
        limit = 24
    else:
        label_expr = "strftime('%H:%M', created_at)"
        since_clause = ""
        limit = 8

    rows = get_db().execute(
        f"""
        SELECT label, count
        FROM (
            SELECT {label_expr} AS label, COUNT(*) AS count, MIN(created_at) AS first_seen
            FROM detection_logs
            {since_clause}
            GROUP BY label
            ORDER BY first_seen DESC
            LIMIT ?
        )
        ORDER BY first_seen
        """,
        (limit,),
    ).fetchall()
    if not rows:
        return {"labels": ["Now"], "values": [0]}
    return {
        "labels": [row["label"] for row in rows],
        "values": [row["count"] for row in rows],
    }


def list_active_threats(limit=3):
    return get_db().execute(
        """
        SELECT *
        FROM detection_logs
        WHERE severity IN ('Critical', 'High', 'Medium')
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

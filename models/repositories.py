import json
from datetime import datetime, timedelta, timezone

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


def _parse_utc_timestamp(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


def _floor_time(value, minutes=60):
    discard = timedelta(
        minutes=value.minute % minutes,
        seconds=value.second,
        microseconds=value.microsecond,
    )
    return value - discard


def threat_timeline(window="live"):
    local_now = datetime.now(timezone.utc).astimezone()

    if window == "7d":
        bucket_count = 7
        bucket_size = timedelta(days=1)
        start = (local_now - timedelta(days=bucket_count - 1)).replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )
        labels = [
            (start + bucket_size * index).strftime("%m/%d")
            for index in range(bucket_count)
        ]
        key_for = lambda value: value.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        ).strftime("%m/%d")
    elif window == "24h":
        bucket_count = 24
        bucket_size = timedelta(hours=1)
        start = _floor_time(local_now, 60) - bucket_size * (bucket_count - 1)
        labels = [
            (start + bucket_size * index).strftime("%H:00")
            for index in range(bucket_count)
        ]
        key_for = lambda value: value.replace(
            minute=0,
            second=0,
            microsecond=0,
        ).strftime("%H:00")
    else:
        bucket_count = 12
        bucket_size = timedelta(minutes=5)
        start = _floor_time(local_now, 5) - bucket_size * (bucket_count - 1)
        labels = [
            (start + bucket_size * index).strftime("%H:%M")
            for index in range(bucket_count)
        ]
        key_for = lambda value: _floor_time(value, 5).strftime("%H:%M")

    since_utc = start.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rows = get_db().execute(
        """
        SELECT created_at
        FROM detection_logs
        WHERE datetime(created_at) >= datetime(?)
        ORDER BY created_at ASC, id ASC
        """,
        (since_utc,),
    ).fetchall()

    values = dict.fromkeys(labels, 0)
    for row in rows:
        local_created = _parse_utc_timestamp(row["created_at"]).astimezone(local_now.tzinfo)
        label = key_for(local_created)
        if label in values:
            values[label] += 1

    return {
        "labels": labels,
        "values": [values[label] for label in labels],
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

import json
from datetime import datetime, timedelta, timezone

from database.db import get_db
from services.ml_service import extract_url_features, url_indicators, url_pattern_profile


def create_url_scan(result, scan_source="URL Scanner"):
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
        scan_source=scan_source,
        action_taken=result["action"],
        summary_text=result.get("summary"),
        indicators=result.get("important_indicators", []),
        pattern=result.get("pattern_profile", {}),
        commit=False,
    )
    db.commit()


def create_email_scan(result, scan_source="Email Analyzer"):
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
        scan_source=scan_source,
        action_taken=result["action"],
        summary_text=result.get("summary"),
        indicators=result.get("important_indicators", result.get("reasons", [])),
        pattern=result.get("pattern_profile", {}),
        commit=False,
    )
    upsert_email_pattern(result, commit=False)
    db.commit()


def create_detection_log(
    target_source,
    severity,
    threat_type,
    ai_confidence,
    scan_source,
    action_taken,
    summary_text=None,
    indicators=None,
    pattern=None,
    commit=True,
):
    db = get_db()
    db.execute(
        """
        INSERT INTO detection_logs
        (target_source, severity, threat_type, ai_confidence, scan_source, action_taken, summary_text, indicators_json, pattern_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_source,
            severity,
            threat_type,
            ai_confidence,
            scan_source,
            action_taken,
            summary_text,
            json.dumps(indicators or []),
            json.dumps(pattern or {}),
        ),
    )
    if commit:
        db.commit()


def upsert_email_pattern(result, commit=True):
    pattern = result.get("pattern_profile") or {}
    pattern_key = pattern.get("pattern_key")
    if not pattern_key:
        return

    db = get_db()
    db.execute(
        """
        INSERT INTO learned_email_patterns
        (pattern_key, pattern_label, severity, observation_count, confidence_total, indicators_json)
        VALUES (?, ?, ?, 1, ?, ?)
        ON CONFLICT(pattern_key) DO UPDATE SET
            pattern_label = excluded.pattern_label,
            severity = excluded.severity,
            observation_count = observation_count + 1,
            confidence_total = confidence_total + excluded.confidence_total,
            indicators_json = excluded.indicators_json,
            last_seen = CURRENT_TIMESTAMP
        """,
        (
            pattern_key,
            result["classification"],
            result["severity"],
            result["ml_confidence"],
            json.dumps(result.get("important_indicators", result.get("reasons", []))),
        ),
    )
    if commit:
        db.commit()


def _json_value(value, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _enrich_log(row):
    item = dict(row)
    item["indicators"] = _json_value(item.get("indicators_json"), [])
    item["pattern"] = _json_value(item.get("pattern_json"), {})
    if not item.get("summary_text"):
        item["summary_text"] = (
            f"{item['threat_type']} was recorded from {item['scan_source']} "
            f"with {round(float(item['ai_confidence'] or 0))}% confidence."
        )
    if not item["indicators"]:
        item["indicators"] = _fallback_indicators(item)
    if not item["pattern"] and "URL" in item["scan_source"]:
        item["pattern"] = _fallback_url_pattern(item["target_source"])
    return item


def _fallback_indicators(item):
    if "URL" in item["scan_source"] or item["target_source"].startswith(("http://", "https://", "www.")):
        try:
            features = extract_url_features(item["target_source"])
            return url_indicators(features, round(float(item["ai_confidence"] or 0)))
        except Exception:
            pass

    indicators = [
        f"Severity was recorded as {item['severity']}.",
        f"Response action was {item['action_taken']}.",
        f"Triage confidence was {round(float(item['ai_confidence'] or 0))}%.",
    ]
    if item["threat_type"] != "Benign":
        indicators.append(f"The event was classified as {item['threat_type']}, so it should be reviewed before trusting the source.")
    else:
        indicators.append("The event was classified as benign because no high-risk evidence was stored with this older scan.")
    return indicators


def _fallback_url_pattern(target_source):
    try:
        return url_pattern_profile(extract_url_features(target_source))
    except Exception:
        return {}


def list_recent_logs(limit=8):
    rows = get_db().execute(
        "SELECT * FROM detection_logs ORDER BY created_at DESC, id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_enrich_log(row) for row in rows]


def list_all_logs():
    rows = get_db().execute(
        "SELECT * FROM detection_logs ORDER BY created_at DESC, id DESC"
    ).fetchall()
    return [_enrich_log(row) for row in rows]


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

    if window == "all":
        rows = get_db().execute(
            """
            SELECT created_at
            FROM detection_logs
            ORDER BY created_at ASC, id ASC
            """
        ).fetchall()
        if not rows:
            return {"labels": ["No data"], "values": [0]}

        first = _parse_utc_timestamp(rows[0]["created_at"]).astimezone(local_now.tzinfo)
        last = _parse_utc_timestamp(rows[-1]["created_at"]).astimezone(local_now.tzinfo)
        day_span = max((last.date() - first.date()).days, 0)

        if day_span > 45:
            labels = []
            cursor = first.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            end = last.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            while cursor <= end:
                labels.append(cursor.strftime("%m/%Y"))
                year = cursor.year + (1 if cursor.month == 12 else 0)
                month = 1 if cursor.month == 12 else cursor.month + 1
                cursor = cursor.replace(year=year, month=month)
            key_for = lambda value: value.strftime("%m/%Y")
        else:
            labels = [
                (first.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=index)).strftime("%m/%d")
                for index in range(day_span + 1)
            ]
            key_for = lambda value: value.replace(
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            ).strftime("%m/%d")

        values = dict.fromkeys(labels, 0)
        for row in rows:
            local_created = _parse_utc_timestamp(row["created_at"]).astimezone(local_now.tzinfo)
            label = key_for(local_created)
            if label in values:
                values[label] += 1
        return {"labels": labels, "values": [values[label] for label in labels]}

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

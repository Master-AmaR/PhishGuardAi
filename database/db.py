import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db():
    if "db" not in g:
        db_path = Path(current_app.config["DATABASE"])
        db_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    with app.app_context():
        db = get_db()
        schema_path = Path(__file__).with_name("schema.sql")
        db.executescript(schema_path.read_text(encoding="utf-8"))
        ensure_schema_upgrades(db)
        db.commit()


def ensure_schema_upgrades(db):
    columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(detection_logs)").fetchall()
    }
    upgrades = {
        "summary_text": "ALTER TABLE detection_logs ADD COLUMN summary_text TEXT",
        "indicators_json": "ALTER TABLE detection_logs ADD COLUMN indicators_json TEXT",
        "pattern_json": "ALTER TABLE detection_logs ADD COLUMN pattern_json TEXT",
    }
    for column, statement in upgrades.items():
        if column not in columns:
            db.execute(statement)

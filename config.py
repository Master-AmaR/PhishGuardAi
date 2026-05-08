import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
    DATABASE = os.getenv("DATABASE_URL", str(BASE_DIR / "database" / "phishguard.db"))
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    MAX_CONTENT_LENGTH = 4 * 1024 * 1024
    ALLOWED_EMAIL_EXTENSIONS = {"eml", "txt"}
    ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", str(BASE_DIR / "ml_models" / "url_model.joblib"))
    LOG_FILE = str(BASE_DIR / "logs" / "phishguard.log")

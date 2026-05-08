from pathlib import Path
from urllib.parse import urlparse


def is_valid_url(value):
    parsed = urlparse(value if "://" in value else f"http://{value}")
    return bool(parsed.netloc and "." in parsed.netloc)


def allowed_file(filename, allowed_extensions):
    return "." in filename and Path(filename).suffix.lower().lstrip(".") in allowed_extensions

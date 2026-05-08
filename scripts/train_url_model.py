import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.pipeline import Pipeline

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.ml_service import extract_url_features, url_model_features


def read_urls(path):
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def suspicious_variants(url):
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    path = parsed.path or "/"
    brand = "amazon" if "amazon" in host else "flipkart" if "flipkart" in host else "shop"
    return [
        f"http://192.168.1.20/{brand}/login?url={url}",
        f"https://{brand}.secure-login.example.com/account/verify?url={url}",
        f"https://{host}.gift-card.example.net{path}?return_url={url}",
        f"http://{host.replace('.', '-')}.account-update.example.org/password/reset",
    ]


def build_dataset(legit_urls):
    rows = []
    labels = []
    for url in legit_urls:
        rows.append(url_model_features(extract_url_features(url)))
        labels.append("legit")
        for suspicious_url in suspicious_variants(url):
            rows.append(url_model_features(extract_url_features(suspicious_url)))
            labels.append("suspicious")
    return rows, labels


def main():
    parser = argparse.ArgumentParser(description="Train the PhishGuard URL pattern model.")
    parser.add_argument("patterns", help="Text file containing known legitimate URL patterns.")
    parser.add_argument("--output", default="ml_models/url_model.joblib", help="Model output path.")
    args = parser.parse_args()

    legit_urls = read_urls(args.patterns)
    if not legit_urls:
        raise SystemExit("No URL patterns found.")

    rows, labels = build_dataset(legit_urls)
    model = Pipeline(
        [
            ("features", DictVectorizer()),
            ("classifier", RandomForestClassifier(n_estimators=120, random_state=42, class_weight="balanced")),
        ]
    )
    model.fit(rows, labels)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    print(f"Trained URL model with {len(legit_urls)} legit patterns and {len(rows) - len(legit_urls)} suspicious variants.")
    print(f"Saved model to {output_path}")


if __name__ == "__main__":
    main()

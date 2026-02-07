"""
URL feature extraction for phishing/malware classification.
Used by both training (modeltraining/train.py) and inference (main.py).
"""
import re
from urllib.parse import urlparse


def extract_features(url):
    """
    Extract a fixed-size numeric feature vector from a URL for ML models.
    Returns a list of numbers (one sample) so that training can use
    .apply(extract_features).tolist() and inference can use predict([extract_features(url)]).
    """
    try:
        url = str(url).lower().strip()
        if not url or url == "nan":
            return [0] * 9
        # Normalize for parsing; skip if it looks like raw IPv6 to avoid urlparse errors
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        hostname = parsed.netloc or ""
        path = parsed.path or ""
        features = [
            len(url),
            url.count("."),
            url.count("-"),
            path.count("/"),
            1 if "@" in url else 0,
            1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname) else 0,
            1 if url.startswith("https") else 0,
            1 if any(word in url for word in ["login", "verify", "bank", "secure"]) else 0,
            1 if any(s in hostname for s in ["bit.ly", "t.co", "goo.gl"]) else 0,
        ]
        return features
    except (ValueError, Exception):
        return [0] * 9

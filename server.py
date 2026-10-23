import csv
from email.utils import parseaddr
import ipaddress
import json
import os
import re
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from sklearn.ensemble import RandomForestClassifier


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "training_data.csv"
SUSPICIOUS_TERMS = (
    "account", "bank", "confirm", "gift", "immediately", "invoice", "login",
    "password", "payment", "prize", "refund", "secure", "suspended", "urgent",
    "verify", "wallet", "update", "click",
)
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd")
HIGH_RISK = "High Risk"


def extract_features(url, message):
    candidate = url.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or "").lower()
    lowered_url = candidate.lower()
    lowered_message = message.lower()
    combined = f"{lowered_url} {lowered_message}"

    try:
        ipaddress.ip_address(host)
        is_ip_address = 1
    except ValueError:
        is_ip_address = 0

    return [
        len(candidate),
        len(host),
        host.count("."),
        candidate.count("-"),
        candidate.count("@"),
        sum(character.isdigit() for character in candidate),
        int(parsed.scheme.lower() == "https"),
        is_ip_address,
        int(any(shortener in host for shortener in SHORTENERS)),
        len(parsed.query),
        len(parsed.path),
        len(message),
        sum(lowered_url.count(term) for term in SUSPICIOUS_TERMS),
        sum(lowered_message.count(term) for term in SUSPICIOUS_TERMS),
        len(re.findall(r"[!$%]", combined)),
    ]


def train_model():
    with DATASET_PATH.open(newline="", encoding="utf-8") as dataset_file:
        rows = list(csv.DictReader(dataset_file))

    if not rows or {row["label"] for row in rows} != {"legitimate", "phishing"}:
        raise ValueError("training_data.csv must contain both legitimate and phishing examples")

    features = [extract_features(row["url"], row["message"]) for row in rows]
    labels = [row["label"] for row in rows]
    classifier = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        max_features="sqrt",
        min_samples_leaf=2,
        random_state=42,
    )
    classifier.fit(features, labels)
    return classifier


MODEL = train_model()


def inspect_email_domains(message):
    from_value = next(
        (line.partition(":")[2].strip() for line in message.splitlines() if line.lower().startswith("from:")),
        "",
    )
    if not from_value:
        return None, None

    display_name, sender_address = parseaddr(from_value)
    sender_domain = sender_address.rsplit("@", 1)[-1].lower() if "@" in sender_address else ""
    claimed_domains = re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
        display_name.lower(),
    )
    sender_mismatch = next(
        ((domain, sender_domain) for domain in claimed_domains if domain != sender_domain),
        None,
    )
    links = re.findall(r"(?i)href\s*=\s*[\"']([^\"']+)[\"']", message)
    link_mismatch = next(
        (
            (urlsplit(link).hostname or "").lower()
            for link in links
            if (urlsplit(link).hostname or "").lower() not in claimed_domains
        ),
        None,
    )
    return sender_mismatch, link_mismatch


def analyze(url, message):
    features = extract_features(url, message)
    probabilities = MODEL.predict_proba([features])[0]
    phishing_index = list(MODEL.classes_).index("phishing")
    score = round(float(probabilities[phishing_index]) * 100)

    if score >= 70:
        severity = HIGH_RISK
        recommendation = "Treat this as suspicious. Do not open the link; verify the request through the organization's official website or contact channel."
    elif score >= 40:
        severity = "Moderate Risk"
        recommendation = "Review the sender and destination carefully. Confirm the request through a trusted channel before taking action."
    else:
        severity = "Low Risk"
        recommendation = "The demo model found fewer phishing signals. This is not a guarantee of safety; check the sender and domain before proceeding."

    findings = []
    content_findings = []
    lowered = f"{url} {message}".lower()
    matched_terms = [term for term in SUSPICIOUS_TERMS if term in lowered]
    if matched_terms:
        content_findings.append(f"Suspicious wording found: {', '.join(matched_terms[:4])}.")
    if url.count("-") >= 2:
        content_findings.append("The URL contains multiple hyphens, which can appear in lookalike domains.")
    if "@" in url:
        content_findings.append("The URL contains an @ character, which can obscure the actual destination.")

    sender_mismatch, link_mismatch = inspect_email_domains(message)
    if sender_mismatch:
        claimed_domain, sender_domain = sender_mismatch
        findings.append(f"Sender display name claims {claimed_domain}, but the address uses {sender_domain}.")
        score = max(score, 85)
        severity = HIGH_RISK
        recommendation = "The sender name and email domain do not match. Do not reply or open links; verify the message through the claimed organization's official contact channel."

    if link_mismatch:
        findings.append(f"Confirmation link leads to {link_mismatch}, not the claimed organization domain.")
        score = max(score, 95)
        severity = HIGH_RISK
        recommendation = "Do not click the confirmation link or reply. The sender and link domains do not match the claimed organization; verify through its official website or contact channel."

    findings.extend(content_findings)
    if not findings:
        findings.append("No common suspicious wording or URL pattern was found.")

    return {
        "score": score,
        "severity": severity,
        "label": "Phishing" if score >= 50 else "Likely legitimate",
        "findings": findings[:4],
        "recommendation": recommendation,
    }


class PhishGuardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_POST(self):
        if self.path != "/api/analyze":
            self.send_error(404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 20000:
                raise ValueError("Request body must be between 1 and 20000 bytes")
            payload = json.loads(self.rfile.read(content_length))
            url = str(payload.get("url", "")).strip()[:2000]
            message = str(payload.get("message", "")).strip()[:10000]
            if not url and not message:
                raise ValueError("Enter a URL or message to scan")
            self.send_json(200, analyze(url, message))
        except ValueError as error:
            self.send_json(400, {"error": str(error)})

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"Random Forest demo ready at http://localhost:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), PhishGuardHandler).serve_forever()

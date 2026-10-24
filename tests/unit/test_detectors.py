import pytest
from redactproof.schemas import TextItem, BoundingBox, FindingCategory
from redactproof.detectors.regex import RegexDetector
from redactproof.detectors.secrets import SecretsDetector, luhn_check, shannon_entropy
from redactproof.detectors.ip import IPAndHostDetector
from redactproof.detectors.local_paths import LocalPathDetector
from redactproof.detectors.url import URLDetector

def test_regex_detector():
    detector = RegexDetector()
    items = [
        TextItem(region_id=1, text="Contact alice@company.com for access", bbox=BoundingBox(x1=0, y1=0, x2=100, y2=20)),
        TextItem(region_id=2, text="AWS_KEY=AKIAIOSFODNN7EXAMPLE", bbox=BoundingBox(x1=0, y1=25, x2=100, y2=45)),
        TextItem(region_id=3, text="ghp_1234567890abcdefghijklmnopqrstuvwxyzAB", bbox=BoundingBox(x1=0, y1=50, x2=100, y2=70)),
    ]
    findings = detector.detect(items)
    categories = [f.category for f in findings]
    assert FindingCategory.PERSONAL_IDENTITY in categories
    assert FindingCategory.CREDENTIAL in categories
    assert len(findings) == 3

def test_secrets_detector_luhn():
    # Valid Visa card (4532 0150 0000 0007)
    valid_card = "4532 0150 0000 0007"
    assert luhn_check(valid_card) is True
    # Invalid card
    assert luhn_check("4532 0150 0000 0005") is False

def test_secrets_entropy():
    # High entropy random base64 string
    high_ent = "aF83jK91_mZ0qWpLsD8vNk2"
    assert shannon_entropy(high_ent) > 3.8

    # Low entropy repetitive string
    low_ent = "aaaaaaaaaaaaaaaaaaaaaa"
    assert shannon_entropy(low_ent) < 1.0

def test_ip_and_host_detector():
    detector = IPAndHostDetector()
    items = [
        TextItem(region_id=1, text="Server running at 192.168.1.100:8080", bbox=BoundingBox(x1=0, y1=0, x2=100, y2=20)),
        TextItem(region_id=2, text="Staging url: auth-svc.staging.cluster.local", bbox=BoundingBox(x1=0, y1=25, x2=100, y2=45)),
    ]
    findings = detector.detect(items)
    assert len(findings) == 2
    assert all(f.category == FindingCategory.INTERNAL_HOSTNAME for f in findings)

def test_local_path_detector():
    detector = LocalPathDetector()
    items = [
        TextItem(region_id=1, text="Error in /Users/johndoe/projects/secret/main.py line 40", bbox=BoundingBox(x1=0, y1=0, x2=100, y2=20))
    ]
    findings = detector.detect(items)
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.LOCAL_PATH_USER

def test_url_detector_with_token_and_allowlist():
    detector = URLDetector()
    items = [
        TextItem(region_id=1, text="https://docs.python.org/3/library/json.html", bbox=BoundingBox(x1=0, y1=0, x2=100, y2=20)),
        TextItem(region_id=2, text="https://api.service.com/webhook?token=supersecret12345", bbox=BoundingBox(x1=0, y1=25, x2=100, y2=45)),
    ]
    findings = detector.detect(items, allowlist_domains=["docs.python.org"])
    assert len(findings) == 2
    # First is allowed / keep
    allowed = next(f for f in findings if f.region_id == 1)
    assert allowed.action.value == "keep"
    # Second is token leak / redact
    leaked = next(f for f in findings if f.region_id == 2)
    assert leaked.action.value == "redact"

import pytest
from redactproof.policy.loader import PolicyLoader
from redactproof.policy.engine import PolicyEngine
from redactproof.schemas import Finding, FindingCategory, Action, BoundingBox, Sensitivity

def test_asymmetric_authority_prevents_downgrade():
    policy = PolicyLoader.load_policy("public")
    engine = PolicyEngine(policy)

    # Deterministic finding: AWS Key marked REDACT
    deterministic = [
        Finding(
            region_id=1,
            bbox=BoundingBox(x1=10, y1=10, x2=100, y2=30),
            category=FindingCategory.CREDENTIAL,
            detector="regex_aws",
            action=Action.REDACT,
            sensitivity=Sensitivity.CRITICAL,
        )
    ]

    # Model maliciously or mistakenly tries to mark it KEEP
    model_finding = [
        Finding(
            region_id=1,
            bbox=BoundingBox(x1=10, y1=10, x2=100, y2=30),
            category=FindingCategory.PUBLIC_PACKAGE_NAME,
            detector="gemma",
            action=Action.KEEP,
            rationale="Fake benign classification",
            sensitivity=Sensitivity.LOW,
        )
    ]

    # Apply policy
    final_findings = engine.apply_policy(
        deterministic_findings=deterministic,
        model_findings=model_finding,
    )

    assert len(final_findings) == 1
    # MUST REMAIN REDACT! Model downgrade was blocked!
    assert final_findings[0].action == Action.REDACT

def test_asymmetric_authority_allows_escalation():
    policy = PolicyLoader.load_policy("public")
    engine = PolicyEngine(policy)

    # Ambiguous finding initially marked KEEP or default
    deterministic = [
        Finding(
            region_id=2,
            bbox=BoundingBox(x1=10, y1=50, x2=100, y2=70),
            category=FindingCategory.PUBLIC_PACKAGE_NAME,
            detector="regex",
            action=Action.KEEP,
            sensitivity=Sensitivity.LOW,
        )
    ]

    # Model discovers relational risk and escalates to REVIEW or REDACT
    model_finding = [
        Finding(
            region_id=2,
            bbox=BoundingBox(x1=10, y1=50, x2=100, y2=70),
            category=FindingCategory.CUSTOMER_IDENTITY,
            detector="gemma",
            action=Action.REVIEW,
            rationale="Disclosed named customer in confidential context",
            sensitivity=Sensitivity.HIGH,
        )
    ]

    final_findings = engine.apply_policy(
        deterministic_findings=deterministic,
        model_findings=model_finding,
    )

    assert len(final_findings) == 1
    # Escalation to REVIEW is allowed!
    assert final_findings[0].action == Action.REVIEW

import pytest
from redactproof.policy.loader import PolicyLoader
from redactproof.policy.engine import PolicyEngine
from redactproof.schemas import Finding, FindingCategory, Action, BoundingBox

def test_load_builtin_policies():
    for name in ["public", "internal", "support"]:
        policy = PolicyLoader.load_policy(name)
        assert policy.policy == name
        assert len(policy.rules) > 0
        assert policy.sha256 is not None
        assert len(policy.sha256) == 64

def test_policy_actions():
    policy = PolicyLoader.load_policy("public")
    engine = PolicyEngine(policy)

    # In public policy, credentials and personal identities must be REDACT
    assert engine.resolve_action_for_category("credential") == Action.REDACT
    assert engine.resolve_action_for_category("personal_identity") == Action.REDACT
    assert engine.resolve_action_for_category("public_package_name") == Action.KEEP

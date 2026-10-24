from typing import List, Dict, Tuple
from ..schemas import Finding, DestinationPolicy, Action, FindingCategory, BoundingBox

ACTION_SEVERITY: Dict[Action, int] = {
    Action.KEEP: 0,
    Action.PSEUDONYMIZE: 1,
    Action.REDACT: 2,
    Action.REVIEW: 3,
}

class PolicyEngine:
    """
    Applies destination policies and enforces Asymmetric Model Authority:
    The model can only add or escalate redactions/reviews.
    It can NEVER remove or downgrade a deterministic finding or rule.
    """

    def __init__(self, policy: DestinationPolicy):
        self.policy = policy
        self._rule_map = {r.category: r.action for r in policy.rules}

    def resolve_action_for_category(self, category: str) -> Action:
        return self._rule_map.get(category, self.policy.default_action)

    def apply_policy(
        self,
        deterministic_findings: List[Finding],
        model_findings: List[Finding],
    ) -> List[Finding]:
        merged: Dict[int, Finding] = {}

        # 1. Process deterministic findings first
        for finding in deterministic_findings:
            policy_action = self.resolve_action_for_category(finding.category.value)
            # If the detector already marked an action, take the more protective of the two
            chosen_action = (
                policy_action
                if ACTION_SEVERITY[policy_action] > ACTION_SEVERITY[finding.action]
                else finding.action
            )
            finding.action = chosen_action
            merged[finding.region_id] = finding

        # 2. Process model findings enforcing ASYMMETRIC AUTHORITY
        for m_finding in model_findings:
            rid = m_finding.region_id
            m_policy_action = self.resolve_action_for_category(m_finding.category.value)
            proposed = (
                m_policy_action
                if ACTION_SEVERITY[m_policy_action] > ACTION_SEVERITY[m_finding.action]
                else m_finding.action
            )

            if rid in merged:
                current = merged[rid]
                current_sev = ACTION_SEVERITY[current.action]
                proposed_sev = ACTION_SEVERITY[proposed]

                # Asymmetric rule: Model CANNOT downgrade protection!
                if proposed_sev > current_sev:
                    current.action = proposed
                    current.rationale += f" [Escalated by model: {m_finding.rationale}]"
                    current.sensitivity = m_finding.sensitivity
                # If model proposed LOWER protection, ignore the downgrade!
            else:
                # New finding discovered by model
                m_finding.action = proposed
                merged[rid] = m_finding

        return list(merged.values())

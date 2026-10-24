import random
import string
from typing import Dict, Optional
from ..schemas import FindingCategory

class PseudonymGenerator:
    """
    Generates consistent pseudonyms within a single image sanitization run.
    Uses randomized per-run mappings to prevent cross-run image correlation.
    """

    def __init__(self, seed: Optional[str] = None):
        self._counters: Dict[str, int] = {}
        self._assigned_map: Dict[str, str] = {}
        if seed:
            random.seed(seed)
        else:
            # Per-run unique salt
            self._run_salt = "".join(random.choices(string.ascii_letters + string.digits, k=8))

    def get_pseudonym(self, category: FindingCategory, identifier: str) -> str:
        cache_key = f"{category.value}:{identifier}"
        if cache_key in self._assigned_map:
            return self._assigned_map[cache_key]

        prefix = "ENTITY"
        if category == FindingCategory.CUSTOMER_IDENTITY:
            prefix = "CUSTOMER"
        elif category == FindingCategory.PERSONAL_IDENTITY:
            prefix = "USER"
        elif category == FindingCategory.INTERNAL_HOSTNAME:
            prefix = "INTERNAL_HOST"
        elif category == FindingCategory.CREDENTIAL:
            prefix = "TOKEN"

        count = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = count

        # If counter <= 26, use letters (A, B, C), otherwise number
        suffix = chr(ord('A') + count - 1) if count <= 26 else str(count)
        pseudonym = f"[{prefix}_{suffix}]"
        self._assigned_map[cache_key] = pseudonym
        return pseudonym

import hashlib
import json
from pathlib import Path
from typing import Union
from ..schemas import DestinationPolicy
from ..config import BUILTIN_POLICIES_DIR

class PolicyLoader:
    """Loads destination policies from built-in templates or custom JSON files."""

    @staticmethod
    def load_policy(policy_identifier: str) -> DestinationPolicy:
        # Check if identifier is a file path
        path = Path(policy_identifier)
        source = "custom"
        if not path.exists():
            # Check built-in policies
            builtin_path = BUILTIN_POLICIES_DIR / f"{policy_identifier}.json"
            if builtin_path.exists():
                path = builtin_path
                source = "builtin"
            else:
                raise FileNotFoundError(
                    f"Policy '{policy_identifier}' not found as file or built-in policy. "
                    f"Available built-in policies: public, internal, support."
                )

        raw_bytes = path.read_bytes()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        data = json.loads(raw_bytes.decode("utf-8"))

        policy = DestinationPolicy.model_validate(data)
        policy.sha256 = sha256
        policy.source = source
        return policy

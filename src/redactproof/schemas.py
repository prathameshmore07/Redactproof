from enum import Enum
from typing import List, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field

class Action(str, Enum):
    KEEP = "keep"
    REDACT = "redact"
    PSEUDONYMIZE = "pseudonymize"
    REVIEW = "review"

class Sensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FindingCategory(str, Enum):
    CREDENTIAL = "credential"
    PERSONAL_IDENTITY = "personal_identity"
    CUSTOMER_IDENTITY = "customer_identity"
    INTERNAL_HOSTNAME = "internal_hostname"
    LOCAL_PATH_USER = "local_path_user"
    FACE_OR_AVATAR = "face_or_avatar"
    QR_OR_BARCODE = "qr_or_barcode"
    PUBLIC_PACKAGE_NAME = "public_package_name"
    PROMPT_INJECTION_ATTEMPT = "prompt_injection_attempt"
    AMBIGUOUS = "ambiguous"
    OTHER = "other"

class BoundingBox(BaseModel):
    # Normalized [0, 1] or pixel coords [x1, y1, x2, y2]
    x1: int
    y1: int
    x2: int
    y2: int

    @property
    def width(self) -> int:
        return max(0, self.x2 - self.x1)

    @property
    def height(self) -> int:
        return max(0, self.y2 - self.y1)

    def to_tuple(self) -> Tuple[int, int, int, int]:
        return (self.x1, self.y1, self.x2, self.y2)

    def intersects(self, other: "BoundingBox") -> bool:
        return not (
            self.x2 < other.x1 or
            self.x1 > other.x2 or
            self.y2 < other.y1 or
            self.y1 > other.y2
        )

    def union(self, other: "BoundingBox") -> "BoundingBox":
        return BoundingBox(
            x1=min(self.x1, other.x1),
            y1=min(self.y1, other.y1),
            x2=max(self.x2, other.x2),
            y2=max(self.y2, other.y2),
        )

class TextItem(BaseModel):
    region_id: int
    text: str
    bbox: BoundingBox
    confidence: float = 1.0

class Finding(BaseModel):
    region_id: int
    bbox: BoundingBox
    category: FindingCategory
    detector: str  # "regex", "secrets", "apple_vision", "gemma", etc.
    confidence: float = 1.0
    action: Action = Action.REDACT
    text_length: int = 0
    text_salted_sha256: str = ""
    plaintext: Optional[str] = None  # None by default, only included if opt-in
    rationale: str = ""
    sensitivity: Sensitivity = Sensitivity.HIGH
    pseudonym_label: Optional[str] = None
    is_residual: bool = False

class RelationalRisk(BaseModel):
    region_ids: List[int]
    inference: str
    proposed_action: Action = Action.REDACT

class PolicyRule(BaseModel):
    category: str
    action: Action

class PolicyAllowlist(BaseModel):
    domains: List[str] = Field(default_factory=list)
    packages: List[str] = Field(default_factory=list)
    patterns: List[str] = Field(default_factory=list)

class PolicyVerificationConfig(BaseModel):
    max_fix_passes: int = 2
    on_residual_finding: str = "block"  # "block" or "flag"

class DestinationPolicy(BaseModel):
    policy: str
    version: int = 2
    default_action: Action = Action.REVIEW
    rules: List[PolicyRule]
    review_threshold: str = "medium"
    allowlist: PolicyAllowlist = Field(default_factory=PolicyAllowlist)
    verification: PolicyVerificationConfig = Field(default_factory=PolicyVerificationConfig)
    sha256: Optional[str] = None
    source: str = "builtin"

class VerifiedFacts(BaseModel):
    masks_uniform: bool = True
    verifier_ocr_hits_in_masks: int = 0
    pattern_hits_after: int = 0
    trailing_bytes: int = 0
    metadata_markers_found: int = 0
    input_unmodified: bool = True

class AssessedJudgments(BaseModel):
    stranger_test_before: List[str] = Field(default_factory=list)
    stranger_test_after: List[str] = Field(default_factory=list)
    adversary_residual_findings: int = 0
    fix_passes_used: int = 0

class ResidualRiskReport(BaseModel):
    level: str = "not_zero"
    notes: List[str] = Field(default_factory=lambda: [
        "AI-based detection can miss sensitive information.",
        "This report does not prove the image is safe for any audience.",
        "This report makes no regulatory compliance claim."
    ])

class AuditReport(BaseModel):
    tool: str = "redactproof"
    version: str = "0.1.0-alpha"
    status: str = "sanitized_verified_with_residual_model_risk"
    input: Dict[str, Any]
    output: Optional[Dict[str, Any]] = None
    policy: Dict[str, Any]
    models: Dict[str, str]
    findings: List[Dict[str, Any]]
    transformations: Dict[str, Any]
    verified: VerifiedFacts
    assessed: AssessedJudgments
    residual_risk: ResidualRiskReport = Field(default_factory=ResidualRiskReport)

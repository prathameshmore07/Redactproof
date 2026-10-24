from typing import List, Optional
from pydantic import BaseModel, Field
from ..schemas import FindingCategory, Action, Sensitivity

class ModelFindingItem(BaseModel):
    region_id: int
    category: str
    sensitivity: str = "high"
    confidence: float = 0.8
    rationale: str = ""
    proposed_action: str = "redact"

class ModelRelationalRisk(BaseModel):
    region_ids: List[int]
    inference: str
    proposed_action: str = "redact"

class ModelReviewResponse(BaseModel):
    findings: List[ModelFindingItem] = Field(default_factory=list)
    relational_risks: List[ModelRelationalRisk] = Field(default_factory=list)

class ModelStrangerTestResponse(BaseModel):
    inferences: List[str] = Field(default_factory=list)

class ModelAdversaryResponse(BaseModel):
    residual_findings: List[str] = Field(default_factory=list)
    clean: bool = True

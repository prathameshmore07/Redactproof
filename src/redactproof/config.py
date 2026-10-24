from pathlib import Path
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BUILTIN_POLICIES_DIR = Path(__file__).resolve().parent / "policy" / "policies"

class Settings(BaseModel):
    tool_name: str = "redactproof"
    version: str = "0.1.0-alpha"
    default_policy: str = "public"
    default_margin_px: int = 4
    default_max_fix_passes: int = 2
    ollama_url: str = "http://localhost:11434"
    gemma_model: str = "gemma4:e2b"  # fallback to gemma4:e4b if available
    gemma_timeout_seconds: float = 30.0
    strict_mode_default: bool = False
    salt_length: int = 16

settings = Settings()

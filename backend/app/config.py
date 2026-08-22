from dataclasses import dataclass
from pathlib import Path
import os


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent


@dataclass(frozen=True)
class Settings:
    openrouter_api_key: str | None
    openrouter_model: str
    allowed_origins: tuple[str, ...]
    runtime_dir: Path
    aws_profile: str = "whs-team"
    aws_region: str = "us-east-1"
    terraform_dir: Path = PROJECT_ROOT / "infra" / "terraform"
    backend_context: Path = BACKEND_ROOT


def get_settings() -> Settings:
    origins = os.getenv(
        "ALLOWED_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    )
    return Settings(
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY") or None,
        openrouter_model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        allowed_origins=tuple(value.strip() for value in origins.split(",") if value.strip()),
        runtime_dir=BACKEND_ROOT / "runtime",
        aws_profile=os.getenv("AWS_PROFILE", "whs-team"),
        aws_region=os.getenv("AWS_REGION", "us-east-1"),
        terraform_dir=PROJECT_ROOT / "infra" / "terraform",
        backend_context=BACKEND_ROOT,
    )

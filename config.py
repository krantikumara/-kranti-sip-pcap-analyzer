"""
config.py - Configuration for Kranti's PCAP Analyzer
Loads credentials from .env file in the same directory.

.env file format (no quotes needed):
    AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
    AZURE_OPENAI_API_KEY=your-api-key
    AZURE_OPENAI_DEPLOYMENT=gpt-4o
    AZURE_OPENAI_API_VERSION=2024-12-01-preview
"""
import os
from pathlib import Path


def _strip_quotes(v: str) -> str:
    """Remove surrounding quotes that some .env editors add."""
    v = v.strip()
    if len(v) >= 2 and v[0] in ('"', "'") and v[-1] == v[0]:
        v = v[1:-1]
    return v.strip()


# ── Load .env file ────────────────────────────────────────────────────────────
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    with open(_env_path, encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _val = _line.partition("=")
                os.environ[_key.strip()] = _strip_quotes(_val)
    print(f"[Config] Loaded .env from {_env_path}")
else:
    print(f"[Config] No .env found at {_env_path} — using system environment variables")

# ── Azure OpenAI ──────────────────────────────────────────────────────────────
AZURE_OPENAI_ENDPOINT    = _strip_quotes(os.environ.get("AZURE_OPENAI_ENDPOINT",    ""))
AZURE_OPENAI_API_KEY     = _strip_quotes(os.environ.get("AZURE_OPENAI_API_KEY",     ""))
AZURE_OPENAI_DEPLOYMENT  = _strip_quotes(os.environ.get("AZURE_OPENAI_DEPLOYMENT",  "gpt-4o"))
AZURE_OPENAI_API_VERSION = _strip_quotes(os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"))

# ── App settings ──────────────────────────────────────────────────────────────
APP_TITLE   = "Kranti's PCAP Analyzer"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 7860


# ── Validate ──────────────────────────────────────────────────────────────────
def credentials_ok():
    return bool(
        AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY
        and not AZURE_OPENAI_ENDPOINT.startswith('"')
        and "YOUR" not in AZURE_OPENAI_ENDPOINT
        and "YOUR" not in AZURE_OPENAI_API_KEY
    )

from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = APP_DIR / "data"

# --- Versioning Unifié ---
ENGINE_VERSION = "0.2.7"
SCAN_MODE = "stealth"

# --- Limites & Sécurité ---
MAX_HTTP_REQUESTS_PER_SCAN: int = 50
MAX_CONCURRENT_REQUESTS: int = 5
RESPONSE_RAW_MAX_BYTES: int = 262_144

# --- Timeouts granulaires (A.2) ---
HTTP_TIMEOUT_CONNECT: float = 5.0
HTTP_TIMEOUT_READ: float = 15.0
HTTP_TIMEOUT_WRITE: float = 10.0
HTTP_TIMEOUT_POOL: float = 5.0

DNS_TIMEOUT: float = 2.0
TLS_TIMEOUT: float = 5.0

# --- Stealth Scheduler (A.1, A.3) ---
GLOBAL_RATE_LIMIT: float = 1.5
ENABLE_JITTER: bool = True
JITTER_RANGE: tuple[float, float] = (0.2, 0.7)

# --- Résilience (A.2) ---
MAX_RETRIES: int = 3
BACKOFF_FACTOR: float = 2.0

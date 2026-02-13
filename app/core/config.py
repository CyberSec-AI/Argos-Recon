from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = APP_DIR / "data"

# --- Versioning Unifié (Source de vérité) ---
ENGINE_VERSION = "0.2.7"

# --- Limites & Sécurité ---
MAX_HTTP_REQUESTS_PER_SCAN: int = 50
MAX_CONCURRENT_REQUESTS: int = 5
RESPONSE_RAW_MAX_BYTES: int = 262_144

# --- Timeouts globaux (Requis par les scanners TLS, DNS, etc.) ---
HTTP_TIMEOUT_TOTAL: float = 30.0
HTTP_TIMEOUT_CONNECT: float = 5.0
DNS_TIMEOUT: float = 2.0
TLS_TIMEOUT: float = 5.0

# --- Phase A : Stealth & Resilience (Roadmap v0.3.0) ---
SCAN_MODE = "stealth"

# A.1 Global Scheduler (Intervalle minimum entre départs)
GLOBAL_RATE_LIMIT: float = 1.5

# A.2 Backoff & Retries
MAX_RETRIES: int = 3
BACKOFF_FACTOR: float = 2.0

# A.3 Jitter
ENABLE_JITTER: bool = True
JITTER_RANGE: tuple[float, float] = (0.2, 0.7)

# A.4 Rotation User-Agent
USER_AGENT_POOL: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

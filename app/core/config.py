from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = APP_DIR / "data"

# --- Versioning Unifié (Source de vérité) ---
ENGINE_VERSION = "0.2.7"

# --- Limites & Sécurité ---
MAX_HTTP_REQUESTS_PER_SCAN: int = 50
MAX_CONCURRENT_REQUESTS: int = 5
RESPONSE_RAW_MAX_BYTES: int = 262_144

# --- Timeouts granulaires (A.2 - Résilience) ---
HTTP_TIMEOUT_TOTAL: float = 30.0
HTTP_TIMEOUT_CONNECT: float = 5.0  # Fail-fast sur cible injoignable
HTTP_TIMEOUT_READ: float = 15.0  # Tolérance pour serveurs lents
HTTP_TIMEOUT_WRITE: float = 10.0
HTTP_TIMEOUT_POOL: float = 5.0  # Evite l'attente infinie sur pool saturé

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

from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = APP_DIR / "data"

# Limites & Sécurité
MAX_HTTP_REQUESTS_PER_SCAN = 50  # Budget total (combien de requêtes max)
MAX_CONCURRENT_REQUESTS = 10  # Concurrence (combien en parallèle) - Nouveau
RESPONSE_RAW_MAX_BYTES = 262_144  # 256KB

# Timeouts (en secondes)
# On augmente le total pour accommoder la latence réseau
HTTP_TIMEOUT_TOTAL = 30.0
HTTP_TIMEOUT_CONNECT = 10.0
DNS_TIMEOUT = 2.0
TLS_TIMEOUT = 5.0

SCAN_MODE = "low_noise"
ENGINE_VERSION = "0.2.5-rc"

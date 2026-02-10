from pathlib import Path

# Calcul robuste : on remonte de app/core/config.py vers la racine app/
# .parents[0] = app/core
# .parents[1] = app
APP_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = APP_DIR / "data"

# Limites & Sécurité
MAX_HTTP_REQUESTS_PER_SCAN = 50
RESPONSE_RAW_MAX_BYTES = 262_144  # 256KB

# Timeouts (en secondes)
HTTP_TIMEOUT_TOTAL = 10.0
DNS_TIMEOUT = 2.0
TLS_TIMEOUT = 5.0

# Profils
SCAN_MODE = "low_noise"
ENGINE_VERSION = "0.2.0-gold"
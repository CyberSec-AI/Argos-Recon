from __future__ import annotations
from typing import List, Optional
from app.schemas.types import SignalV1, TLSArtifactV1, HTTPRequestArtifactV1
import ulid

def extract_signals(
    tls_artifact: Optional[TLSArtifactV1], 
    http_artifacts: List[HTTPRequestArtifactV1]
) -> List[SignalV1]:
    
    signals = []
    
    # --- Signals TLS (Protection contre None) ---
    if tls_artifact:
        # Check 1: Subject Match
        # On utilise une chaîne vide par défaut si cn est None
        cn = tls_artifact.cn or ""
        host = tls_artifact.observed_host or ""
        
        # Logique exemple (à adapter selon tes besoins réels)
        match_subject = (cn.lower() == host.lower())
        
        signals.append(SignalV1(
            signal_id="tls.subject_mismatch",
            source="tls",
            target_id=tls_artifact.target_id,
            value=(not match_subject),
            signal_confidence=0.9
        ))
        
        # Check 2: Issuer (Exemple)
        issuer = tls_artifact.issuer_o or ""
        is_letsencrypt = "Let's Encrypt" in issuer
        signals.append(SignalV1(
            signal_id="tls.issuer_type",
            source="tls",
            target_id=tls_artifact.target_id,
            value="letsencrypt" if is_letsencrypt else "other",
            signal_confidence=0.7
        ))

    # --- Signals HTTP ---
    if http_artifacts:
        baseline = http_artifacts[0]
        # Check Headers
        server = baseline.headers.get("server", "").lower()
        signals.append(SignalV1(
            signal_id="http.header.verbose",
            source="http",
            target_id=baseline.target_id,
            value=("nginx" in server or "apache" in server),
            signal_confidence=0.6
        ))

    return signals
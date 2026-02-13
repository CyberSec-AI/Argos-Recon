from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from app.schemas.types import HTTPRequestArtifactV1, SignalV1, TLSArtifactV1


def extract_signals(
    tls_artifact: Optional[TLSArtifactV1], http_artifacts: List[HTTPRequestArtifactV1]
) -> List[SignalV1]:
    signals = []

    if tls_artifact:
        cn = tls_artifact.cn or ""
        host = tls_artifact.observed_host or ""
        is_mismatch = (cn.lower() != host.lower()) if cn else False

        if cn:
            signals.append(
                SignalV1(
                    signal_id="tls.subject_mismatch",
                    source="tls",
                    target_id=tls_artifact.target_id,
                    value=is_mismatch,
                    signal_confidence=0.9,
                )
            )

        # Logique d'expiration ISO 8601
        is_expired = False
        if tls_artifact.not_after:
            try:
                # Normalisation Z -> +00:00
                iso_date = tls_artifact.not_after.replace("Z", "+00:00")
                expiry_dt = datetime.fromisoformat(iso_date)
                if expiry_dt < datetime.now(timezone.utc):
                    is_expired = True
            except ValueError:
                pass

        # Fallback sur erreur explicite
        if not is_expired and tls_artifact.error and "expired" in tls_artifact.error.lower():
            is_expired = True

        signals.append(
            SignalV1(
                signal_id="tls.is_expired",
                source="tls",
                target_id=tls_artifact.target_id,
                value=is_expired,
                signal_confidence=1.0,
            )
        )

    if http_artifacts:
        baseline = http_artifacts[0]
        server = baseline.headers.get("server", "").lower()
        if server:
            signals.append(
                SignalV1(
                    signal_id="http.header.verbose",
                    source="http",
                    target_id=baseline.target_id,
                    value=("nginx" in server or "apache" in server),
                    signal_confidence=0.6,
                )
            )

    return signals

from __future__ import annotations
from typing import Optional, List
import ulid
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingSignalRefV1, FindingEvidenceRefV1, BurpArtifactsV1, BurpNextActionV1
from app.schemas.types import SignalV1, HTTPRequestArtifactV1

def evaluate_pb2(signals: List[SignalV1], target: dict, http_artifacts: List[HTTPRequestArtifactV1]) -> Optional[FindingV1]:
    spec_sig = next((s for s in signals if s.signal_id == "surface.api.spec_exposed" and s.value), None)
    ui_sig = next((s for s in signals if s.signal_id == "surface.api.ui_exposed" and s.value), None)

    trigger_sig = spec_sig or ui_sig
    if not trigger_sig:
        return None

    finding_id = str(ulid.new())
    
    # Résolution URL précise via artifact
    found_url = target["canonical_url"]
    req_id = trigger_sig.artifact_ref
    if req_id:
        art = next((a for a in http_artifacts if a.request_id == req_id), None)
        if art:
            found_url = art.effective_url or art.url

    # Contextualisation
    if spec_sig:
        title = "OpenAPI/Swagger Specification Exposed"
        summary = "Full API definition file (JSON/YAML) is publicly accessible."
        severity = "high"
        desc = "The exposed specification allows generating a full client to interact with the API, revealing all endpoints."
    else:
        title = "API Documentation UI Exposed"
        summary = "Swagger UI or GraphiQL interface is accessible."
        severity = "medium"
        desc = "Interactive documentation allows exploring and testing API endpoints directly."

    return FindingV1(
        finding_id=finding_id,
        playbook_id="PB2_API_EXPOSURE",
        title=title,
        summary=summary,
        severity=severity,
        confidence="high",
        score=FindingScoreV1(total=1, threshold=1, model="bool.v1"),
        target=FindingTargetRefV1(
            target_id=target["target_id"],
            input=target["input"],
            canonical_url=target["canonical_url"]
        ),
        reasoning={
            "why_it_matters": desc,
            "correlation": [f"Probed path {found_url} returned 200 OK with specific API content."],
            "analyst_notes": "Verify if endpoints are intended to be public. If internal, restrict access immediately."
        },
        signals=[
            FindingSignalRefV1(signal_id=trigger_sig.signal_id, value=True, artifact_ref=trigger_sig.artifact_ref)
        ],
        evidence=[
            FindingEvidenceRefV1(
                evidence_id=f"ev_{ulid.new()}",
                type="http_probe",
                ref={"request_id": trigger_sig.artifact_ref},
                snippet="API content detected (OpenAPI keys or UI keywords)."
            )
        ],
        burp_artifacts=BurpArtifactsV1(
            urls=[found_url],
            requests=[trigger_sig.artifact_ref] if trigger_sig.artifact_ref else [],
            next_actions=[
                BurpNextActionV1(
                    type="audit",
                    title="Audit exposed API endpoints",
                    suggested_paths=[],
                    caution="Respect rate limits."
                )
            ]
        )
    )
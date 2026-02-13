from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config import ENGINE_VERSION
from app.services.scan_engine import ScanEngine

router = APIRouter()
engine = ScanEngine()  # Note: Instance unique, initialisée une fois.


class AnalyzeRequest(BaseModel):
    url: str


@router.get("/health")
def health():
    return {"status": "online", "version": ENGINE_VERSION}


@router.post("/analyze")
async def analyze(req: AnalyzeRequest):
    result = await engine.run(req.url)
    if result.get("status") == "failed":
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

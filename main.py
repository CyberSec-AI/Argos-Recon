from fastapi import FastAPI

from app.api.routes import router
from app.core.config import ENGINE_VERSION
from app.core.logging import setup_logging


def create_app() -> FastAPI:
    setup_logging("INFO")
    # Utilisation de la version centralisée
    app = FastAPI(
        title="Argos Recon",
        version=ENGINE_VERSION,
        description="Moteur d'analyse de surface d'attaque",
    )
    app.include_router(router)
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    # Note: reload=True uniquement en local dev
    uvicorn.run("main:app", host="0.0.0.0", port=8000)

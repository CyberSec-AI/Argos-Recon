from fastapi import FastAPI

from app.api.routes import router
from app.core.logging import setup_logging


def create_app() -> FastAPI:
    setup_logging("INFO")
    app = FastAPI(title="Argos Recon", version="0.2.0")
    app.include_router(router)
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

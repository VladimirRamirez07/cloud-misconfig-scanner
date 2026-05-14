from fastapi import FastAPI
from app.database.db import engine
from app.database import models
from app.api.routes import router

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Cloud Misconfiguration Scanner",
    description="Detecta misconfiguraciones en AWS basado en CIS Benchmarks. Simula Prowler.",
    version="1.0.0"
)

app.include_router(router, prefix="/api/v1")

@app.get("/")
def root():
    return {
        "tool": "Cloud Misconfiguration Scanner",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "running"
    }
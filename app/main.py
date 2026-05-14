from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.database.db import engine
from app.database import models
from app.api.routes import router

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Cloud Misconfiguration Scanner",
    description="Detecta misconfiguraciones en AWS basado en CIS Benchmarks. Simula Prowler.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/dashboard", StaticFiles(directory="app", html=True), name="dashboard")
app.include_router(router, prefix="/api/v1")

@app.get("/")
def root():
    return {
        "tool": "Cloud Misconfiguration Scanner",
        "version": "1.0.0",
        "docs": "/docs",
        "dashboard": "/dashboard/dashboard.html",
        "status": "running"
    }
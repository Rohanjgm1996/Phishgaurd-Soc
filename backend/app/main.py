"""
PhishGuard SOC - FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings, ensure_dirs
from app.models.database import init_db
from app.api.auth import router as auth_router
from app.api.analyze import router as analyze_router
from app.api.reports import router as reports_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create dirs, init DB, seed demo user."""
    ensure_dirs()
    await init_db()
    print(f"[PhishGuard] {settings.APP_NAME} v{settings.APP_VERSION} started")
    yield
    print("[PhishGuard] Shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="SOC-grade phishing email and attachment analysis platform",
    lifespan=lifespan,
)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(analyze_router)
app.include_router(reports_router)


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs",
    }

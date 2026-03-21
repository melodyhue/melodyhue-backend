#!/usr/bin/env python3
import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from .routes import (
    public,
    auth,
    users,
    overlays,
    settings,
    spotify,
    admin,
    modo,
    realtime,
)
from .services.state import get_state
from .services.cleanup import cleanup_scheduler
from .utils.database import create_all


log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI(title="MelodyHue API", version=os.getenv("APP_VERSION", "4.4.4"))

# ── Public API CORS: /infos, /color, /overlay → Access-Control-Allow-Origin: * ──
_PUBLIC_PREFIXES = ("/infos/", "/color/", "/overlay/")


class _PublicAPICORSMiddleware(BaseHTTPMiddleware):
    """Allow any origin on public read-only API endpoints."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        is_public = any(request.url.path.startswith(p) for p in _PUBLIC_PREFIXES)

        if is_public and request.method == "OPTIONS":
            response = Response(status_code=204)
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
            response.headers["Access-Control-Max-Age"] = "86400"
            return response

        response = await call_next(request)

        if is_public:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"

        return response


# CORS (configurable)
if os.getenv("ENABLE_CORS", "false").lower() == "true":
    origins_env = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
    # Liste d'origines séparées par des virgules
    allow_origins = [o.strip() for o in origins_env.split(",") if o.strip()] or ["*"]
    allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"
    # Si wildcard et credentials=true, les navigateurs refusent: forcer credentials à false
    if "*" in allow_origins and allow_credentials:
        logging.warning(
            "CORS: '*' avec credentials=true n'est pas supporté par les navigateurs; credentials sera forcé à false."
        )
        allow_credentials = False

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Public API middleware (must be added AFTER CORSMiddleware → runs as outer layer)
app.add_middleware(_PublicAPICORSMiddleware)

state = get_state()
_cleanup_stop_event = None
_cleanup_task = None

# Include routers
app.include_router(public.router, tags=["public"])  # /infos, /color
app.include_router(
    auth.router, prefix="/auth", tags=["auth"]
)  # /auth/login, /auth/register, ...
app.include_router(users.router, prefix="/users", tags=["users"])  # profile updates
app.include_router(
    overlays.router, prefix="/overlays", tags=["overlays"]
)  # CRUD overlays
app.include_router(
    settings.router, prefix="/settings", tags=["settings"]
)  # user settings
app.include_router(spotify.router, prefix="/spotify", tags=["spotify"])
app.include_router(
    admin.router, prefix="/admin", tags=["admin"]
)  # admin dashboard & roles
app.include_router(modo.router, prefix="/modo", tags=["moderation"])  # moderator tools
app.include_router(realtime.router, tags=["realtime"])  # /ws


@app.on_event("startup")
async def on_startup():
    try:
        create_all(None)
    except Exception:
        pass
    await state.start()
    # Démarrer la tâche de nettoyage en arrière-plan
    import asyncio

    global _cleanup_stop_event, _cleanup_task
    _cleanup_stop_event = asyncio.Event()
    _cleanup_task = asyncio.create_task(cleanup_scheduler(_cleanup_stop_event))


@app.on_event("shutdown")
async def on_shutdown():
    await state.stop()
    # Arrêter le scheduler
    try:
        if _cleanup_stop_event is not None:
            _cleanup_stop_event.set()
        if _cleanup_task is not None:
            await _cleanup_task
    except Exception:
        pass


# Simple health
@app.get("/health")
async def health():
    return {"status": "ok"}

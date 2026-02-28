"""Detect Email — Main application entry point.

Starts:
  1. FastAPI REST API on port 8000 (for HTTP-based access)
  2. aiosmtpd SMTP server on port 1025 (for direct email reception)

Both share the same AI cascade: L1 → L2 → L3 → Operator.
"""

# Fix LD_LIBRARY_PATH BEFORE any heavy C/C++ libraries are loaded
# Conda env ships newer libstdc++ (with CXXABI_1.3.15) needed by ICU / llama-cpp.
# Without this, Playwright (Chromium) and llama-cpp fail at runtime.
import os as _os
import sys as _sys

_conda_prefix = _os.environ.get("CONDA_PREFIX", "")
if _conda_prefix:
    _conda_lib = _os.path.join(_conda_prefix, "lib")
    _ld = _os.environ.get("LD_LIBRARY_PATH", "")
    if _conda_lib not in _ld:
        _os.environ["LD_LIBRARY_PATH"] = f"{_conda_lib}:{_ld}" if _ld else _conda_lib
        # For the *current* process, also pre-load the correct libstdc++
        try:
            import ctypes
            _libstdcpp = _os.path.join(_conda_lib, "libstdc++.so.6")
            if _os.path.exists(_libstdcpp):
                ctypes.CDLL(_libstdcpp)
        except Exception:
            pass  # best-effort; subprocess (Playwright) will pick up env var

import asyncio
import json
import logging
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.config import settings
from app import events
from app import operator_store
from app.schemas import Label, OperatorDecision, Verdict
from app.layer_toggle import layer_state, set_layer, get_layers

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# SMTP controller reference
_smtp_controller = None

# Path to static files
_STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: startup and shutdown."""
    global _smtp_controller

    logger.info("Detect Email -- AI Phishing Defense System")

    # --- Startup ---
    # 1. Start SMTP server
    from app.gateway.smtp_handler import start_smtp_server
    _smtp_controller = start_smtp_server(
        host=settings.smtp_host,
        port=settings.smtp_port,
    )
    logger.info("[SMTP] Listening on %s:%d", settings.smtp_host, settings.smtp_port)

    # 2. Pre-load L2 model
    try:
        from app.l2_classifier.service import load_model as load_l2
        load_l2()
        logger.info("[L2] DistilBERT model loaded")
    except Exception as e:
        logger.warning("[L2] Model not pre-loaded (will load on first request): %s", e)

    # 3. L3 Judge (heavy — lazy load)
    logger.info("[L3] DeepSeek Judge will load on first Grey Zone email (~15 GB VRAM)")

    logger.info("System ready")
    logger.info("  API:       http://%s:%d", settings.api_host, settings.api_port)
    logger.info("  SMTP:      %s:%d", settings.smtp_host, settings.smtp_port)
    logger.info("  Dashboard: http://%s:%d/", settings.api_host, settings.api_port)
    logger.info("  Swagger:   http://%s:%d/docs", settings.api_host, settings.api_port)

    yield

    # --- Shutdown ---
    if _smtp_controller:
        _smtp_controller.stop()
        logger.info("[SMTP] Server stopped")

    logger.info("Detect Email shut down.")


# FastAPI App

app = FastAPI(
    title="Detect Email — AI Phishing Defense",
    description="Multi-layer AI cascade for phishing email detection (L1 → L2 → L3 → Operator)",
    version="1.1.0",
    lifespan=lifespan,
)

# Register routers
from app.gateway.router import router as gateway_router
from app.l1_threat_intel.router import router as l1_router
from app.l2_classifier.router import router as l2_router
from app.l3_orchestrator.router import router as l3_orchestrator_router
from app.l3_judge.router import router as l3_judge_router

app.include_router(gateway_router)
app.include_router(l1_router)
app.include_router(l2_router)
app.include_router(l3_orchestrator_router)
app.include_router(l3_judge_router)


# Favicon (inline SVG shield)

_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
    '<defs><linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">'
    '<stop offset="0%" style="stop-color:#3b82f6"/>'
    '<stop offset="100%" style="stop-color:#06b6d4"/>'
    '</linearGradient></defs>'
    '<path d="M50 5 L90 25 L90 55 C90 75 70 92 50 98 C30 92 10 75 10 55 L10 25 Z" '
    'fill="url(#g)" stroke="#1e40af" stroke-width="2"/>'
    '<text x="50" y="62" text-anchor="middle" font-size="36" '
    'font-weight="bold" font-family="Arial" fill="white">AI</text>'
    '</svg>'
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Serve inline SVG favicon."""
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml")


# Dashboard (HTML UI)

@app.get("/", response_class=HTMLResponse, tags=["System"])
async def dashboard():
    """Serve the web dashboard for the phishing detection system."""
    html_path = _STATIC_DIR / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="<h1>Detect Email</h1><p>Dashboard file not found.</p>",
        status_code=200,
    )


# Layer Toggle API

@app.get("/api/v1/layers", tags=["System"])
async def get_layer_state():
    """Get current state of protection layers (enabled/disabled)."""
    return get_layers()


class LayerToggle(BaseModel):
    layer: str
    enabled: bool


@app.post("/api/v1/layers", tags=["System"])
async def set_layer_state(toggle: LayerToggle):
    """Enable or disable a protection layer (L1, L2, L3)."""
    ok = set_layer(toggle.layer, toggle.enabled)
    if not ok:
        return {"error": f"Unknown layer: {toggle.layer}"}

    await events.publish("layer_toggle", "", "system", {
        "layer": toggle.layer,
        "enabled": toggle.enabled,
        "layers": get_layers(),
    })

    return {"status": "ok", "layers": get_layers()}


# JSON API Info

@app.get("/api/info", tags=["System"])
async def api_info():
    """System overview in JSON format."""
    return {
        "service": "Detect Email — AI Phishing Defense",
        "version": "1.1.0",
        "architecture": {
            "L1": "Threat Intel — URL/IP/domain reputation",
            "L2": "Classifier — DistilBERT text classification",
            "L3": "Orchestrator — Evidence Agent + DeepSeek-R1 Judge",
            "Operator": "Human review for uncertain verdicts",
            "Retrain": "DistilBERT incremental fine-tuning on operator decisions",
        },
        "smtp": f"{settings.smtp_host}:{settings.smtp_port}",
    }


# WebSocket for real-time events

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket endpoint for real-time processing events."""
    await ws.accept()
    queue = await events.subscribe()

    try:
        history = events.get_history()
        if history:
            await ws.send_text(json.dumps({
                "type": "history",
                "events": history[-50:],
            }))
    except Exception:
        pass

    try:
        while True:
            event = await queue.get()
            await ws.send_text(json.dumps(event))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await events.unsubscribe(queue)


@app.get("/api/events/history", tags=["System"])
async def events_history():
    """Get recent processing events."""
    return {"events": events.get_history()[-100:]}


# Operator Review API

@app.get("/api/v1/operator/pending", tags=["Operator"])
async def operator_pending():
    """Get all emails awaiting operator review."""
    pending = operator_store.get_pending()
    return {"count": len(pending), "items": [p.dict() for p in pending]}


@app.post("/api/v1/operator/decide", tags=["Operator"])
async def operator_decide(decision: OperatorDecision):
    """Submit operator's classification for an uncertain email."""
    ok = operator_store.resolve_pending(decision)
    if not ok:
        return {"error": f"Email {decision.email_id} not found in pending queue"}

    # Broadcast operator decision event
    await events.publish("operator_decision", decision.email_id, "operator", {
        "label": decision.operator_label.value,
        "comment": decision.comment,
    })

    total = operator_store.get_decision_count()
    return {
        "status": "ok",
        "email_id": decision.email_id,
        "label": decision.operator_label.value,
        "total_decisions": total,
        "retrain_ready": total >= 10,
        "message": f"Labeled as {decision.operator_label.value}. "
                   f"{'Ready to retrain!' if total >= 10 else f'{10 - total} more needed for retraining.'}"
    }


@app.get("/api/v1/operator/decisions", tags=["Operator"])
async def operator_decisions():
    """Get all operator decisions (for review before retraining)."""
    decisions = operator_store.get_decisions()
    return {"count": len(decisions), "items": decisions}


@app.post("/api/v1/operator/retrain", tags=["Operator"])
async def operator_retrain():
    """Trigger incremental DistilBERT retraining using operator decisions.

    Runs the retraining script as a background process and returns immediately.
    """
    decisions = operator_store.get_decisions()
    if len(decisions) < 5:
        return {"error": f"Need at least 5 decisions, have {len(decisions)}"}

    # Write decisions to a temp CSV for the training script
    import csv
    retrain_path = Path("./data/retrain_data.csv")
    retrain_path.parent.mkdir(parents=True, exist_ok=True)

    with open(retrain_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        for d in decisions:
            text = f"{d.get('subject', '')} {d.get('body', '')}"
            label = 1 if d.get("operator_label") == "phishing" else 0
            writer.writerow({"text": text, "label": label})

    await events.publish("retrain_start", "", "system", {
        "message": f"Retraining DistilBERT with {len(decisions)} operator decisions...",
        "count": len(decisions),
    })

    # Start retraining in background
    logger.info("Starting DistilBERT incremental retraining with %d decisions", len(decisions))

    try:
        proc = subprocess.Popen(
            [
                sys.executable, "-m", "app.l2_classifier.train",
                "--incremental", str(retrain_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Don't await — let it run in background
        asyncio.get_event_loop().call_later(
            1.0,
            lambda: _check_retrain(proc),
        )

        return {
            "status": "started",
            "pid": proc.pid,
            "decisions": len(decisions),
            "message": "Retraining started in background. Model will hot-reload when complete."
        }
    except Exception as e:
        return {"error": str(e)}


def _check_retrain(proc):
    """Check if retraining completed (non-blocking poll)."""
    ret = proc.poll()
    if ret is None:
        # Still running, check again later
        asyncio.get_event_loop().call_later(5.0, lambda: _check_retrain(proc))
    elif ret == 0:
        logger.info("DistilBERT retraining completed successfully!")
        # Hot-reload the model
        try:
            from app.l2_classifier import service as l2_svc
            l2_svc._model = None
            l2_svc._tokenizer = None
            l2_svc.load_model()
            logger.info("L2 model hot-reloaded after retraining")
        except Exception as e:
            logger.error("Failed to hot-reload L2 model: %s", e)

        # Clear processed decisions
        operator_store.clear_decisions()
    else:
        logger.error("DistilBERT retraining failed (exit code %d)", ret)


# User Inbox API

@app.get("/api/v1/inbox", tags=["User Inbox"])
async def user_inbox(limit: int = 50):
    """Get user's inbox — delivered/released emails with AI summaries."""
    items = operator_store.get_inbox(limit)
    return {"count": len(items), "items": [i.dict() for i in items]}


@app.post("/api/v1/inbox/clear", tags=["User Inbox"])
async def clear_inbox():
    """Clear the user inbox."""
    operator_store.clear_inbox()
    return {"status": "ok"}


# CLI Entry Point

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
        log_level="info",
    )

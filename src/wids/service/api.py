import argparse
from typing import Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Header, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from sqlmodel import select, text
import uvicorn
import asyncio, json, pathlib

from wids.common import load_config, setup_logging
from wids.db     import get_engine, init_db, session, Event, Alert

app = FastAPI(title="WIDS API")
logger = setup_logging()

cfg = {}
engine = None

# CORS for dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def require_key(x_api_key: Optional[str] = Header(None)):
    wanted = cfg.get("api", {}).get("api_key")
    if wanted and x_api_key != wanted:
        raise HTTPException(status_code=401, detail="Invalid API key")

def get_db():
    with session(engine) as s:
        yield s

@app.get("/api/health")
def health():
    return {"status": "ok", "ts": datetime.utcnow().isoformat()+"Z"}

@app.get("/api/overview", dependencies=[Depends(require_key)])
def overview(db=Depends(get_db)):
    events = db.exec(select(text("count(1)")).select_from(Event)).one()[0]
    alerts = db.exec(select(text("count(1)")).select_from(Alert)).one()[0]
    return {"events": events, "alerts": alerts}

@app.get("/api/alerts", dependencies=[Depends(require_key)])
def list_alerts(limit: int = 100, db=Depends(get_db)):
    rows = db.exec(select(Alert).order_by(Alert.id.desc()).limit(limit)).all()
    return [r.model_dump() for r in rows]

@app.post("/api/alerts/test", dependencies=[Depends(require_key)])
def create_test_alert(db=Depends(get_db)):
    a = Alert(ts=datetime.utcnow(), severity="info", kind="test", summary="hello from WIDS")
    db.add(a); db.commit()
    return {"ok": True, "id": a.id}

@app.get("/api/events", dependencies=[Depends(require_key)])
def list_events(
    since_seconds: int = Query(default=60, ge=0, le=86400),
    type: Optional[str] = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
    db=Depends(get_db),
):
    since = datetime.utcnow() - timedelta(seconds=since_seconds)
    q = select(Event).where(Event.ts >= since)
    if type:
        q = q.where(Event.type == type)
    rows = db.exec(q.order_by(Event.id.desc()).limit(limit)).all()
    return [r.model_dump() for r in rows]

# === SSE: stream new alerts in near real-time ===
subscribers = set()

@app.get("/api/stream")
async def stream(request: Request):
    queue = asyncio.Queue()
    subscribers.add(queue)

    async def gen():
        try:
            # initial hello
            hello = {"hello": True, "ts": datetime.utcnow().isoformat()+"Z"}
            yield f"data: {json.dumps(hello)}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield f"data: {json.dumps(item)}\n\n"
                except asyncio.TimeoutError:
                    # keep connection alive
                    yield ": keep-alive\n\n"
        finally:
            subscribers.discard(queue)

    return Response(gen(), media_type="text/event-stream")

def publish_alert_sse(alert: Alert):
    # called by sensor via direct import is not ideal; normally use a broker.
    # Here we keep it in-process: API and sensor run in the same process only if you embed;
    # For your current split-process setup, SSE will show only test ticks.
    payload = {
        "kind": alert.kind,
        "severity": alert.severity,
        "summary": alert.summary,
        "ts": alert.ts.isoformat()+"Z",
        "id": alert.id,
    }
    for q in list(subscribers):
        try:
            q.put_nowait(payload)
        except Exception:
            pass

def main(config_path: str):
    global cfg, engine
    cfg = load_config(config_path)
    engine = get_engine(cfg["database"]["path"])
    init_db(engine)

    # ensure indexes
    with session(engine) as db:
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_ts ON event(ts);"))
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_type_ts ON event(type, ts);"))
        db.commit()

    # serve built UI if present
    dist = pathlib.Path(__file__).resolve().parents[3] / "ui" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="ui")

    uvicorn.run(app, host=cfg["api"]["bind_host"], port=cfg["api"]["bind_port"])

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    main(args.config)

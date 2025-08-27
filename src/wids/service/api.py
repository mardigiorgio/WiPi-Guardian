import argparse
from typing import Optional
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import select
import uvicorn
from sqlmodel import text

from wids.common import load_config, setup_logging
from wids.db import get_engine, init_db, session, Event, Alert

app = FastAPI(title="WIDS API (minimal)")
logger = setup_logging()

cfg = {}
engine = None

# CORS for dev; tighten later if you want
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
    total_events = db.exec(select(Event)).all()
    total_alerts = db.exec(select(Alert)).all()
    return {"events": len(total_events), "alerts": len(total_alerts)}

@app.get("/api/alerts", dependencies=[Depends(require_key)])
def list_alerts(db=Depends(get_db)):
    rows = db.exec(select(Alert).order_by(Alert.ts.desc()).limit(100)).all()
    return [r.model_dump() for r in rows]

@app.post("/api/alerts/test", dependencies=[Depends(require_key)])
def create_test_alert(db=Depends(get_db)):
    a = Alert(ts=datetime.utcnow(), severity="info", kind="test", summary="hello from WIDS")
    db.add(a); db.commit()
    return {"ok": True, "id": a.id}

def main(config_path: str):
    global cfg, engine
    cfg = load_config(config_path)
    engine = get_engine(cfg["database"]["path"])
    init_db(engine)

    with session(engine) as db:
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_ts ON event(ts);"))
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_type_ts ON event(type, ts);"))
        db.commit()
    logger.info("[db] indexes ensured")

    uvicorn.run(app, host=cfg["api"]["bind_host"], port=cfg["api"]["bind_port"])

if __name__ == "__main__":
    # Allow `python -m wids.service.api --config configs/wids.yaml`
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    main(args.config)

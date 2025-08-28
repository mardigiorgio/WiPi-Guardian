from sqlmodel import SQLModel, Field, create_engine, Session
from typing import Optional
from datetime import datetime
import pathlib
from sqlalchemy import text

class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime
    type: str
    band: str
    chan: int
    src: Optional[str] = None
    dst: Optional[str] = None
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    rssi: Optional[int] = None
    # Optional RSN info captured from beacons (comma-separated selector strings)
    rsn_akms: Optional[str] = None
    rsn_ciphers: Optional[str] = None

class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime
    severity: str     # "info" | "warn" | "critical"
    kind: str         # e.g., "deauth_flood"
    summary: str
    acknowledged: bool = False

def get_engine(db_path: str):
    # Ensure parent directory exists for the SQLite file
    try:
        p = pathlib.Path(db_path)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

def init_db(engine):
    SQLModel.metadata.create_all(engine)

def ensure_schema(engine):
    """Lightweight migration to add new columns if missing."""
    with Session(engine) as s:
        cols = set()
        try:
            rows = s.exec(text("PRAGMA table_info(event)")).all()
            cols = {r[1] for r in rows}
        except Exception:
            pass
        alters = []
        if "rsn_akms" not in cols:
            alters.append("ALTER TABLE event ADD COLUMN rsn_akms TEXT NULL;")
        if "rsn_ciphers" not in cols:
            alters.append("ALTER TABLE event ADD COLUMN rsn_ciphers TEXT NULL;")
        for stmt in alters:
            try:
                s.exec(text(stmt))
            except Exception:
                pass
        s.commit()

def session(engine):
    return Session(engine)

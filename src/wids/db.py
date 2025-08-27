from sqlmodel import SQLModel, Field, create_engine, Session
from typing import Optional
from datetime import datetime

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

class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime
    severity: str     # "info" | "warn" | "critical"
    kind: str         # e.g., "deauth_flood"
    summary: str
    acknowledged: bool = False

def get_engine(db_path: str):
    return create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

def init_db(engine):
    SQLModel.metadata.create_all(engine)

def session(engine):
    return Session(engine)

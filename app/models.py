from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .db import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    customer = Column(String, default="", index=True)
    auth_by = Column(String, default="")        # who gave permission
    auth_date = Column(String, default="")
    auth_ref = Column(String, default="")       # contract / ticket / e-mail reference
    scope_note = Column(Text, default="")
    profile = Column(String, default="standard")
    status = Column(String, default="pending")  # pending, running, completed, failed, cancelled
    log = Column(Text, default="")
    tool_version = Column(String, default="")
    scanner_ip = Column(String, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True))

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    key = Column(String)          # id into knowledge/findings.yaml (texts are rendered at read time)
    category = Column(String)
    severity = Column(String)     # Critical, High, Medium, Low, Info, Pass
    confidence = Column(String)   # low, medium, high
    evidence = Column(Text)
    params = Column(Text, default="{}")   # JSON, used to fill the texts

    scan = relationship("Scan", back_populates="findings")


class CacheEntry(Base):
    __tablename__ = "cache"

    key = Column(String, primary_key=True)
    value = Column(Text)
    fetched_at = Column(Float)

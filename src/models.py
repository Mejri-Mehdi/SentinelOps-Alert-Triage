"""SQLAlchemy database models for Alerts, Cases, and Response Actions."""

from datetime import datetime
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Boolean,
    ForeignKey,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from src.config import DB_PATH

Base = declarative_base()


class Case(Base):
    """Correlated Security Incident containing one or more related alerts."""
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(32), default="open")  # open, contained, closed
    priority = Column(String(32), default="medium")  # low, medium, high, critical
    
    # Entity pivot (what caused the correlation)
    entity_type = Column(String(32), nullable=False)  # ip, user, host
    entity_value = Column(String(128), nullable=False, index=True)
    
    # Risk Metrics
    rule_score = Column(Float, default=0.0)
    ml_score = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0, index=True)
    alert_count = Column(Integer, default=0)
    
    # Relationships
    alerts = relationship("Alert", back_populates="case", cascade="all, delete-orphan")
    actions = relationship("ResponseAction", back_populates="case", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Case(case_id='{self.case_id}', entity='{self.entity_value}', risk={self.risk_score})>"


class Alert(Base):
    """Normalized security telemetry event."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)  # MD5 for deduplication
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String(64), default="synthetic-siem")
    severity = Column(String(32), nullable=False)  # info, low, medium, high, critical
    
    # Key entities for correlation
    source_ip = Column(String(45), nullable=True, index=True)
    user = Column(String(64), nullable=True, index=True)
    host = Column(String(64), nullable=True, index=True)
    
    # Alert content & MITRE mapping
    alert_type = Column(String(64), nullable=False, index=True)
    mitre_technique_id = Column(String(32), nullable=True)
    mitre_technique_name = Column(String(128), nullable=True)
    mitre_tactic = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    
    # Workflow status
    status = Column(String(32), default="ingested")  # ingested, correlated, responded
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    
    case = relationship("Case", back_populates="alerts")

    def __repr__(self):
        return f"<Alert(alert_id='{self.alert_id}', type='{self.alert_type}', sev='{self.severity}')>"


class ResponseAction(Base):
    """Audit log of automated SOAR playbooks and actions executed."""
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    playbook_id = Column(String(64), nullable=False)
    action_type = Column(String(64), nullable=False)  # notify, isolate, disable, block, enrich
    target = Column(String(128), nullable=False)
    details = Column(Text, nullable=True)
    status = Column(String(32), default="completed")  # completed, failed, simulated
    mock = Column(Boolean, default=True)

    case = relationship("Case", back_populates="actions")

    def __repr__(self):
        return f"<ResponseAction(action='{self.action_type}', target='{self.target}', status='{self.status}')>"


def get_engine(db_url: str = None):
    """Create and return an engine."""
    url = db_url or f"sqlite:///{DB_PATH}"
    return create_engine(url, echo=False)


def init_db(engine=None):
    """Create all tables in the database."""
    eng = engine or get_engine()
    Base.metadata.create_all(eng)
    return eng


def get_session(engine=None):
    """Get a new database session."""
    eng = engine or get_engine()
    Session = sessionmaker(bind=eng)
    return Session()

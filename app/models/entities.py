from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON, Enum, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from app.database import Base
import enum

class Role(str, enum.Enum):
    super_admin = "super_admin"
    security_admin = "security_admin"
    security_officer = "security_officer"
    viewer = "viewer"

class CameraStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    maintenance = "maintenance"

class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class IncidentStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    incidents: Mapped[list["Incident"]] = relationship(back_populates="creator")

class Building(Base):
    __tablename__ = "buildings"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cameras: Mapped[list["Camera"]] = relationship(back_populates="building")
    zones: Mapped[list["RiskZone"]] = relationship(back_populates="building")

class Camera(Base):
    __tablename__ = "cameras"
    id: Mapped[int] = mapped_column(primary_key=True)
    camera_name: Mapped[str] = mapped_column(String(120), index=True)
    location: Mapped[str] = mapped_column(String(180), index=True)
    rtsp_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[CameraStatus] = mapped_column(Enum(CameraStatus), default=CameraStatus.offline)
    risk_level: Mapped[str] = mapped_column(String(20), default="safe")
    people_count: Mapped[int] = mapped_column(Integer, default=0)
    last_activity: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    building_id: Mapped[int | None] = mapped_column(ForeignKey("buildings.id"), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    building: Mapped[Building | None] = relationship(back_populates="cameras")
    incidents: Mapped[list["Incident"]] = relationship(back_populates="camera")

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incident_timestamp_severity", "timestamp", "severity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    camera_id: Mapped[int | None] = mapped_column(ForeignKey("cameras.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    location: Mapped[str] = mapped_column(String(180))
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.medium)
    confidence: Mapped[float] = mapped_column(Float)
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.open)
    snapshot_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    timestamp: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    camera: Mapped[Camera | None] = relationship(back_populates="incidents")
    creator: Mapped[User | None] = relationship(back_populates="incidents")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    channel: Mapped[str] = mapped_column(String(30), default="dashboard")
    delivery_status: Mapped[str] = mapped_column(String(30), default="queued")
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    incident: Mapped[Incident] = relationship(back_populates="alerts")

class RiskZone(Base):
    __tablename__ = "risk_zones"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="safe")
    active_cameras: Mapped[int] = mapped_column(Integer, default=0)
    alerts_count: Mapped[int] = mapped_column(Integer, default=0)
    building_id: Mapped[int | None] = mapped_column(ForeignKey("buildings.id"), nullable=True)
    building: Mapped[Building | None] = relationship(back_populates="zones")

class SystemLog(Base):
    __tablename__ = "system_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    token_jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

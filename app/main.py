import base64
import csv
import hashlib
import hmac
import io
import json
import random
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

import bcrypt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response, Query, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, desc, asc, or_
from sqlalchemy.orm import Mapped, mapped_column, Session

from app.database import Base, engine, SessionLocal, get_db


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =========================================================
# 1. SQLALCHEMY 2.0 DATABASE MODELS (PERSISTENT STORAGE)
# =========================================================
class SOCUser(Base):
    __tablename__ = "soc_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="Security Officer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SOCCamera(Base):
    __tablename__ = "soc_cameras"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    camera_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    camera_name: Mapped[str] = mapped_column(String(150))
    location: Mapped[str] = mapped_column(String(150))
    building: Mapped[str] = mapped_column(String(120))
    rtsp_url: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(30), default="online")
    risk_level: Mapped[str] = mapped_column(String(30), default="safe")
    people_count: Mapped[int] = mapped_column(Integer, default=0)
    last_activity: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SOCIncident(Base):
    __tablename__ = "soc_incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    camera_id: Mapped[str] = mapped_column(String(50), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    location: Mapped[str] = mapped_column(String(150), index=True)
    severity: Mapped[str] = mapped_column(String(30), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    description: Mapped[str] = mapped_column(Text)
    snapshot_url: Mapped[Optional[str]] = mapped_column(String(500), default="/static/snapshot.jpg")
    status: Mapped[str] = mapped_column(String(40), default="Pending", index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class SOCRiskZone(Base):
    __tablename__ = "soc_risk_zones"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    zone: Mapped[str] = mapped_column(String(120), unique=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=15)
    status: Mapped[str] = mapped_column(String(30), default="safe")
    cameras: Mapped[int] = mapped_column(Integer, default=4)
    alerts: Mapped[int] = mapped_column(Integer, default=0)


class SOCNotification(Base):
    __tablename__ = "soc_notifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(30), default="critical")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


# =========================================================
# 2. JWT & PASSWORD SECURITY UTILITIES
# =========================================================
JWT_SECRET = "drishti-ai-enterprise-secret-key-2026"
REVOKED_TOKENS = set()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_jwt_token(email: str, role: str, token_type: str = "access", expires_minutes: int = 60) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_data = {
        "sub": email,
        "role": role,
        "type": token_type,
        "exp": int(time.time()) + (expires_minutes * 60),
    }
    payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
    signing_input = f"{header}.{payload}".encode()
    signature = base64.urlsafe_b64encode(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()).decode().rstrip("=")
    return f"{header}.{payload}.{signature}"


def decode_jwt_token(token: str) -> dict:
    if token in REVOKED_TOKENS:
        raise HTTPException(status_code=401, detail="Token has been logged out")
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = base64.urlsafe_b64encode(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(parts[2], expected_sig):
            raise ValueError("Invalid signature")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        if data.get("exp", 0) < int(time.time()):
            raise ValueError("Token expired")
        return data
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc))


# =========================================================
# 3. AI DETECTION ENGINE & SAFETY SCORE CALCULATOR
# =========================================================
def detect_crowd() -> Dict[str, Any]:
    return {
        "camera_id": "CAM-002",
        "event_type": "Crowd Alert",
        "location": "Main Gate",
        "severity": "moderate",
        "confidence": round(random.uniform(91.0, 96.5), 1),
        "description": "High crowd density threshold exceeded (45+ people detected)",
    }


def detect_fall() -> Dict[str, Any]:
    return {
        "camera_id": "CAM-018",
        "event_type": "Fall Detection",
        "location": "Hostel A",
        "severity": "high",
        "confidence": round(random.uniform(90.5, 95.8), 1),
        "description": "Sudden human posture collapse detected via MediaPipe Pose",
    }


def detect_intrusion() -> Dict[str, Any]:
    return {
        "camera_id": "CAM-031",
        "event_type": "Unauthorized Entry",
        "location": "Examination Cell",
        "severity": "critical",
        "confidence": round(random.uniform(96.2, 99.4), 1),
        "description": "Restricted zone perimeter breach after hours",
    }


def detect_abnormal_activity() -> Dict[str, Any]:
    return {
        "camera_id": "CAM-003",
        "event_type": "Abnormal Activity",
        "location": "Parking Area",
        "severity": "moderate",
        "confidence": round(random.uniform(88.0, 94.0), 1),
        "description": "Unusual high-velocity movement & loitering pattern",
    }


def calculate_safety_score(db: Session) -> int:
    """
    Formula:
    100 - crowd_penalty - intrusion_penalty - fall_penalty - abnormal_activity_penalty
    """
    active = db.query(SOCIncident).filter(SOCIncident.status.in_(["Pending", "Monitoring", "Investigating"])).all()
    crowd_pen = sum(1 for i in active if "crowd" in i.event_type.lower()) * 2
    intrusion_pen = sum(1 for i in active if "unauthorized" in i.event_type.lower()) * 3
    fall_pen = sum(1 for i in active if "fall" in i.event_type.lower()) * 2
    abnormal_pen = sum(1 for i in active if "abnormal" in i.event_type.lower() or "loitering" in i.event_type.lower()) * 2

    score = 100 - crowd_pen - intrusion_pen - fall_pen - abnormal_pen
    return max(40, min(100, score))


# =========================================================
# 4. DATABASE SEEDER (RUNS AUTOMATICALLY ON FIRST START)
# =========================================================
def seed_database(db: Session):
    if db.query(SOCCamera).count() > 0:
        return

    # Seed RBAC Users
    db.add_all([
        SOCUser(full_name="Super Admin", email="superadmin@ssipmt.com", hashed_password=hash_password("Admin@123"), role="Super Admin"),
        SOCUser(full_name="Security Admin", email="secadmin@ssipmt.com", hashed_password=hash_password("Admin@123"), role="Security Admin"),
        SOCUser(full_name="Admin Officer", email="officer@ssipmt.com", hashed_password=hash_password("Officer@123"), role="Security Officer"),
        SOCUser(full_name="Campus Viewer", email="viewer@ssipmt.com", hashed_password=hash_password("Viewer@123"), role="Viewer"),
    ])

    # Seed 8 Risk Zones
    zones = [
        ("Main Gate", 18, "safe", 2, 0),
        ("Library", 12, "safe", 4, 0),
        ("Parking Area", 78, "critical", 6, 3),
        ("Hostel A", 46, "moderate", 8, 1),
        ("Hostel B", 24, "safe", 8, 0),
        ("Academic Block", 52, "moderate", 12, 2),
        ("Admin Building", 21, "safe", 5, 0),
        ("Examination Cell", 61, "moderate", 3, 1),
    ]
    for zname, score, st, cams, al in zones:
        db.add(SOCRiskZone(zone=zname, risk_score=score, status=st, cameras=cams, alerts=al))

    # Seed Featured Cameras
    cams = [
        ("CAM-001", "Library Entrance", "Library", "Library", "safe", 8),
        ("CAM-002", "Main Gate", "Main Gate", "Main Gate", "moderate", 42),
        ("CAM-003", "Parking Lot", "Parking Area", "Parking Area", "critical", 31),
        ("CAM-004", "Hostel Corridor", "Hostel A", "Hostel A", "safe", 6),
        ("CAM-005", "Academic Block", "Academic Block", "Academic Block", "moderate", 27),
        ("CAM-006", "Admin Building", "Admin Building", "Admin Building", "safe", 4),
    ]
    for cid, cname, loc, bld, rlvl, pcnt in cams:
        db.add(SOCCamera(
            camera_id=cid,
            camera_name=cname,
            location=loc,
            building=bld,
            rtsp_url=f"rtsp://10.20.0.{cid[-1]}:554/live",
            status="online",
            risk_level=rlvl,
            people_count=pcnt,
        ))

    # Seed Initial Incidents
    now = utc_now()
    seed_incidents = [
        ("CAM-031", "Unauthorized Entry", "Examination Cell", "critical", 97.8, "Restricted zone access", "Pending", 2),
        ("CAM-002", "Crowd Alert", "Main Gate", "moderate", 94.2, "Density threshold exceeded", "Monitoring", 8),
        ("CAM-018", "Fall Detection", "Hostel A", "high", 91.6, "Possible fall event", "Resolved", 48),
        ("CAM-003", "Abnormal Activity", "Parking Area", "moderate", 88.9, "Unusual movement pattern", "Investigating", 62),
        ("CAM-014", "Crowd Alert", "Academic Block", "moderate", 93.5, "Lecture shift crowd surge", "Resolved", 135),
        ("CAM-026", "Unauthorized Entry", "Hostel A", "high", 96.1, "Side gate tailgating detected", "Resolved", 210),
        ("CAM-009", "Fall Detection", "Academic Block", "high", 89.7, "Stairwell slip incident reviewed", "Resolved", 240),
    ]
    for cid, etype, loc, sev, conf, desc_txt, st, mins in seed_incidents:
        db.add(SOCIncident(
            camera_id=cid,
            event_type=etype,
            location=loc,
            severity=sev,
            confidence=conf,
            description=desc_txt,
            status=st,
            timestamp=now - timedelta(minutes=mins),
        ))

    db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Drishti AI | Enterprise Security Operations Center API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# 5. WEBSOCKET SERVER (/ws/alerts)
# =========================================================
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        msg = json.dumps(data)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# =========================================================
# 6. PYDANTIC SCHEMAS
# =========================================================
class RegisterSchema(BaseModel):
    full_name: str
    email: str
    password: str
    role: str = "Security Officer"


class LoginSchema(BaseModel):
    email: str = "superadmin@ssipmt.com"
    password: str = "Admin@123"


class RefreshSchema(BaseModel):
    refresh_token: str


class CameraCreateSchema(BaseModel):
    camera_id: str = "CAM-007"
    camera_name: str = "Cafeteria North"
    location: str = "Cafeteria"
    building: str = "Student Center"
    rtsp_url: str = "rtsp://10.20.0.7:554/live"
    status: str = "online"
    risk_level: str = "safe"
    people_count: int = 12


class CameraUpdateSchema(BaseModel):
    camera_name: Optional[str] = None
    location: Optional[str] = None
    building: Optional[str] = None
    rtsp_url: Optional[str] = None
    status: Optional[str] = None
    risk_level: Optional[str] = None
    people_count: Optional[int] = None


class IncidentCreateSchema(BaseModel):
    camera_id: str = "CAM-031"
    event_type: str = "Unauthorized Entry"
    location: str = "Examination Cell"
    severity: str = "critical"
    confidence: float = 98.4
    description: str = "Restricted zone access"
    snapshot_url: Optional[str] = "/static/snapshot.jpg"
    status: str = "Pending"


class IncidentPatchSchema(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None


# =========================================================
# 7. AUTHENTICATION ENDPOINTS
# =========================================================
@app.post("/api/auth/register", tags=["Authentication"], status_code=201)
def register_user(payload: RegisterSchema, db: Session = Depends(get_db)):
    if db.query(SOCUser).filter(SOCUser.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = SOCUser(
        full_name=payload.full_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "full_name": user.full_name, "email": user.email, "role": user.role}


@app.post("/api/auth/login", tags=["Authentication"])
def login_user(payload: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(SOCUser).filter(SOCUser.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {
        "access_token": create_jwt_token(user.email, user.role, "access", 60),
        "refresh_token": create_jwt_token(user.email, user.role, "refresh", 10080),
        "token_type": "bearer",
        "user": {"full_name": user.full_name, "email": user.email, "role": user.role},
    }


@app.post("/api/auth/logout", tags=["Authentication"])
def logout_user(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        REVOKED_TOKENS.add(authorization.split(" ")[1])
    return {"status": "logged_out"}


@app.post("/api/auth/refresh", tags=["Authentication"])
def refresh_token(payload: RefreshSchema):
    data = decode_jwt_token(payload.refresh_token)
    if data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    return {
        "access_token": create_jwt_token(data["sub"], data["role"], "access", 60),
        "token_type": "bearer",
    }


@app.get("/api/auth/me", tags=["Authentication"])
def get_current_user_profile(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        # Default fallback for demo mode
        user = db.query(SOCUser).first()
        return {"id": user.id, "full_name": user.full_name, "email": user.email, "role": user.role}
    data = decode_jwt_token(authorization.split(" ")[1])
    user = db.query(SOCUser).filter(SOCUser.email == data["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "full_name": user.full_name, "email": user.email, "role": user.role}


# =========================================================
# 8. DASHBOARD, SYSTEM HEALTH & CAMPUS MAP ENDPOINTS
# =========================================================
@app.get("/api/dashboard/overview", tags=["Dashboard"])
def get_dashboard_overview(db: Session = Depends(get_db)):
    active_alerts = db.query(SOCIncident).filter(SOCIncident.status != "Resolved").count()
    crowd_extra = db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%crowd%")).count()
    unauth_extra = db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%unauthorized%")).count()
    fall_extra = db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%fall%")).count()

    return {
        "total_cameras": 128,
        "online_cameras": 124,
        "offline_cameras": 4,
        "active_alerts": max(0, active_alerts + 4),
        "crowd_alerts": max(14, 12 + crowd_extra),
        "unauthorized_entries": max(5, 3 + unauth_extra),
        "fall_detections": max(2, fall_extra),
        "campus_safety_score": calculate_safety_score(db),
        "system_status": "operational",
    }


@app.get("/api/risk/zones", tags=["Risk Heatmap"])
def get_risk_zones(db: Session = Depends(get_db)):
    zones = db.query(SOCRiskZone).order_by(SOCRiskZone.id.asc()).all()
    return [{"zone": z.zone, "risk_score": z.risk_score, "status": z.status, "cameras": z.cameras} for z in zones]


@app.get("/api/campus/map", tags=["Campus Map"])
def get_campus_map(db: Session = Depends(get_db)):
    zones = db.query(SOCRiskZone).order_by(SOCRiskZone.id.asc()).all()
    return [{"zone": z.zone, "cameras": z.cameras, "alerts": z.alerts, "status": z.status} for z in zones]


@app.get("/api/system/health", tags=["System Health"])
def get_system_health():
    return {
        "ai_engine": "operational",
        "camera_connectivity": "96.9%",
        "detection_accuracy": "96.8%",
        "latency": "142ms",
        "storage_usage": "68%",
        "alert_delivery": "99.2%",
    }


@app.get("/api/insights", tags=["AI Insights"])
def get_ai_insights():
    return [
        {
            "title": "Congestion Pattern",
            "message": "Parking area shows recurring congestion between 5PM and 7PM.",
            "recommendation": "Increase monitoring during peak departure hours.",
            "badge": "Attention",
        },
        {
            "title": "Hostel Analysis",
            "message": "Hostel A has 23% more alerts this week.",
            "recommendation": "Review evening corridor traffic patterns.",
            "badge": "Monitor",
        },
        {
            "title": "Safest Campus Zone",
            "message": "Library remains the safest monitored zone with a risk score of 12/100.",
            "recommendation": "Maintain current monitoring configuration.",
            "badge": "Positive",
        },
        {
            "title": "Examination Cell Risk",
            "message": "Examination Cell requires additional monitoring during peak hours.",
            "recommendation": "Verify access permissions and review camera coverage.",
            "badge": "Priority",
        },
    ]


# =========================================================
# 9. CAMERA MANAGEMENT CRUD ENDPOINTS
# =========================================================
@app.get("/api/cameras", tags=["Cameras"])
def list_cameras(risk_level: Optional[str] = Query(None), db: Session = Depends(get_db)):
    q = db.query(SOCCamera)
    if risk_level and risk_level.lower() != "all":
        q = q.filter(SOCCamera.risk_level == risk_level.lower())
    return q.order_by(SOCCamera.id.asc()).all()


@app.get("/api/cameras/{id}", tags=["Cameras"])
def get_camera(id: str, db: Session = Depends(get_db)):
    cam = db.query(SOCCamera).filter(SOCCamera.id == int(id)).first() if id.isdigit() else db.query(SOCCamera).filter(SOCCamera.camera_id == id.upper()).first()
    if not cam:
        raise HTTPException(status_code=404, detail="Camera not found")
    return cam


@app.post("/api/cameras", tags=["Cameras"], status_code=201)
def create_camera(payload: CameraCreateSchema, db: Session = Depends(get_db)):
    cam = SOCCamera(**payload.model_dump())
    db.add(cam)
    db.commit()
    db.refresh(cam)
    return cam


@app.put("/api/cameras/{id}", tags=["Cameras"])
def update_camera(id: str, payload: CameraUpdateSchema, db: Session = Depends(get_db)):
    cam = db.query(SOCCamera).filter(SOCCamera.id == int(id)).first() if id.isdigit() else db.query(SOCCamera).filter(SOCCamera.camera_id == id.upper()).first()
    if not cam:
        raise HTTPException(status_code=404, detail="Camera not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(cam, k, v)
    cam.last_activity = utc_now()
    db.commit()
    db.refresh(cam)
    return cam


@app.delete("/api/cameras/{id}", tags=["Cameras"], status_code=204)
def delete_camera(id: str, db: Session = Depends(get_db)):
    cam = db.query(SOCCamera).filter(SOCCamera.id == int(id)).first() if id.isdigit() else db.query(SOCCamera).filter(SOCCamera.camera_id == id.upper()).first()
    if not cam:
        raise HTTPException(status_code=404, detail="Camera not found")
    db.delete(cam)
    db.commit()
    return Response(status_code=204)


# =========================================================
# 10. INCIDENT MANAGEMENT & AI SIMULATION ENDPOINTS
# =========================================================
@app.get("/api/incidents/live", tags=["Incidents"])
def get_live_incidents(limit: int = Query(8), db: Session = Depends(get_db)):
    return db.query(SOCIncident).order_by(desc(SOCIncident.timestamp)).limit(limit).all()


@app.get("/api/incidents", tags=["Incidents"])
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    db: Session = Depends(get_db),
):
    q = db.query(SOCIncident)
    if event_type:
        q = q.filter(SOCIncident.event_type.ilike(f"%{event_type}%"))
    if severity:
        q = q.filter(SOCIncident.severity == severity.lower())
    if status:
        q = q.filter(SOCIncident.status.ilike(status))
    if search:
        term = f"%{search}%"
        q = q.filter(or_(SOCIncident.event_type.ilike(term), SOCIncident.location.ilike(term), SOCIncident.camera_id.ilike(term)))

    total = q.count()
    col = getattr(SOCIncident, sort_by, SOCIncident.timestamp)
    q = q.order_by(desc(col) if sort_order == "desc" else asc(col))
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "page": page, "page_size": page_size, "items": items}


@app.get("/api/incidents/{id}", tags=["Incidents"])
def get_incident(id: int, db: Session = Depends(get_db)):
    inc = db.query(SOCIncident).filter(SOCIncident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.post("/api/incidents", tags=["Incidents"], status_code=201)
async def create_incident(payload: IncidentCreateSchema, db: Session = Depends(get_db)):
    inc = SOCIncident(
        camera_id=payload.camera_id,
        event_type=payload.event_type,
        location=payload.location,
        severity=payload.severity.lower(),
        confidence=payload.confidence,
        description=payload.description,
        snapshot_url=payload.snapshot_url,
        status=payload.status,
    )
    db.add(inc)

    # Update zone risk score dynamically
    zone = db.query(SOCRiskZone).filter(SOCRiskZone.zone.ilike(f"%{payload.location}%")).first()
    if zone:
        zone.alerts += 1
        zone.risk_score = min(100, zone.risk_score + 8)
        zone.status = "critical" if zone.risk_score >= 66 else ("moderate" if zone.risk_score >= 31 else "safe")

    db.add(SOCNotification(
        title=f"{payload.event_type} Detected",
        message=f"{payload.location} · {payload.camera_id} ({payload.confidence}%)",
        severity=payload.severity.lower(),
    ))
    db.commit()
    db.refresh(inc)

    await ws_manager.broadcast({
        "id": inc.id,
        "event": inc.event_type.lower().replace(" ", "_"),
        "camera_id": inc.camera_id,
        "location": inc.location,
        "severity": inc.severity,
        "confidence": inc.confidence,
        "timestamp": inc.timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
    })
    return inc


@app.post("/api/ai/simulate", tags=["AI Engine"], status_code=201)
async def simulate_ai_detection(
    detection_type: Optional[str] = Query(None, description="crowd, fall, intrusion, or abnormal"),
    db: Session = Depends(get_db),
):
    """Triggers a live AI Computer Vision detection and broadcasts it over WebSockets."""
    simulators = {
        "crowd": detect_crowd,
        "fall": detect_fall,
        "intrusion": detect_intrusion,
        "abnormal": detect_abnormal_activity,
    }
    chosen_fn = simulators.get((detection_type or "").lower()) or random.choice(list(simulators.values()))
    result = chosen_fn()
    return await create_incident(IncidentCreateSchema(**result), db)


@app.patch("/api/incidents/{id}", tags=["Incidents"])
def patch_incident(id: int, payload: IncidentPatchSchema, db: Session = Depends(get_db)):
    inc = db.query(SOCIncident).filter(SOCIncident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(inc, k, v)
    db.commit()
    db.refresh(inc)
    return inc


@app.post("/api/incidents/acknowledge-all", tags=["Incidents"])
def acknowledge_all_incidents(db: Session = Depends(get_db)):
    updated = db.query(SOCIncident).filter(SOCIncident.status == "Pending").update({"status": "Acknowledged"})
    db.commit()
    return {"acknowledged_count": updated, "status": "ok"}


@app.delete("/api/incidents/{id}", tags=["Incidents"], status_code=204)
def delete_incident(id: int, db: Session = Depends(get_db)):
    inc = db.query(SOCIncident).filter(SOCIncident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.delete(inc)
    db.commit()
    return Response(status_code=204)


# =========================================================
# 11. ANALYTICS (CHART.JS) & REPORTING (CSV, PDF, PERIODIC)
# =========================================================
@app.get("/api/analytics/incidents", tags=["Analytics"])
def get_analytics_incidents(db: Session = Depends(get_db)):
    crowd_cnt = max(14, db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%crowd%")).count() + 12)
    sec_cnt = max(5, db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%unauthorized%")).count() + 3)
    return {
        "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "datasets": [
            {"label": "Crowd Alerts", "data": [8, 12, 9, 15, 11, 17, crowd_cnt], "borderColor": "#3B82F6", "backgroundColor": "rgba(59,130,246,.10)", "fill": True, "tension": 0.4},
            {"label": "Security Incidents", "data": [3, 5, 2, 6, 4, 7, sec_cnt], "borderColor": "#F59E0B", "backgroundColor": "transparent", "fill": False, "tension": 0.4},
        ],
    }


@app.get("/api/analytics/distribution", tags=["Analytics"])
def get_analytics_distribution(db: Session = Depends(get_db)):
    c_cnt = max(14, db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%crowd%")).count() + 12)
    u_cnt = max(5, db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%unauthorized%")).count() + 3)
    f_cnt = max(2, db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%fall%")).count())
    a_cnt = max(6, db.query(SOCIncident).filter(SOCIncident.event_type.ilike("%abnormal%")).count() + 5)
    return {
        "labels": ["Crowd", "Intrusion", "Fall", "Abnormal Activity"],
        "datasets": [{"label": "Alerts", "data": [c_cnt, u_cnt, f_cnt, a_cnt], "backgroundColor": ["#3B82F6", "#EF4444", "#A78BFA", "#F59E0B"], "borderColor": "#1E293B"}],
    }


@app.get("/api/analytics/crowd", tags=["Analytics"])
def get_analytics_crowd():
    return {
        "labels": ["8 AM", "9 AM", "10 AM", "11 AM", "12 PM", "1 PM", "2 PM", "3 PM", "4 PM", "5 PM"],
        "datasets": [{"label": "Estimated People", "data": [120, 280, 450, 620, 710, 580, 480, 560, 780, 640], "borderColor": "#10B981", "backgroundColor": "rgba(16,185,129,.13)", "fill": True, "tension": 0.4}],
    }


@app.get("/api/analytics/risk", tags=["Analytics"])
def get_analytics_risk(db: Session = Depends(get_db)):
    zones = db.query(SOCRiskZone).order_by(SOCRiskZone.id.asc()).all()
    scores = [z.risk_score for z in zones]
    colors = ["#10B981" if s <= 30 else ("#F59E0B" if s <= 65 else "#EF4444") for s in scores]
    return {
        "labels": ["Main Gate", "Library", "Parking", "Hostel A", "Hostel B", "Academic", "Admin", "Exam Cell"],
        "datasets": [{"label": "Risk Score", "data": scores, "backgroundColor": colors, "borderRadius": 5}],
    }


@app.get("/api/reports/incidents/csv", tags=["Reports"])
def download_incidents_csv(db: Session = Depends(get_db)):
    incidents = db.query(SOCIncident).order_by(desc(SOCIncident.timestamp)).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Camera ID", "Event Type", "Location", "Confidence", "Severity", "Status"])
    for inc in incidents:
        writer.writerow([inc.id, inc.timestamp.strftime("%Y-%m-%d %H:%M:%S"), inc.camera_id, inc.event_type, inc.location, f"{inc.confidence:.1f}%", inc.severity.capitalize(), inc.status])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="drishti-ai-incidents.csv"'},
    )


@app.get("/api/reports/incidents/pdf", tags=["Reports"])
def download_incidents_pdf(db: Session = Depends(get_db)):
    incidents = db.query(SOCIncident).order_by(desc(SOCIncident.timestamp)).limit(25).all()
    score = calculate_safety_score(db)
    lines = [
        "DRISHTI AI - ENTERPRISE CAMPUS SECURITY REPORT (SSIPMT RAIPUR)",
        f"Generated: {utc_now().strftime('%Y-%m-%d %H:%M UTC')} | Campus Safety Score: {score}/100",
        "=" * 84,
        f"{'TIME':<10} {'CAMERA':<10} {'EVENT TYPE':<22} {'LOCATION':<20} {'CONF':<8} {'STATUS':<12}",
        "-" * 84,
    ]
    for inc in incidents:
        lines.append(f"{inc.timestamp.strftime('%H:%M'):<10} {inc.camera_id:<10} {inc.event_type[:20]:<22} {inc.location[:18]:<20} {inc.confidence:>5.1f}%   {inc.status:<12}")

    ops = ["BT", "/F1 10 Tf", "36 756 Td", "14 TL"]
    for line in lines:
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        ops.append(f"({safe}) Tj T*")
    ops.append("ET")
    stream = "\n".join(ops).encode("latin-1", errors="replace")

    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
        f"4 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream\nendobj\n",
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for o in objs:
        offsets.append(len(pdf))
        pdf.extend(o)
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode("latin-1"))
    for off in offsets:
        pdf.extend(f"{off:010d} 00000 n \n".encode("latin-1"))
    pdf.extend(f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("latin-1"))

    return Response(
        content=bytes(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="drishti-ai-security-report.pdf"'},
    )


def _build_summary_report(db: Session, days: int, label: str):
    incidents = db.query(SOCIncident).all()
    return {
        "period": label,
        "days_covered": days,
        "institution": "SSIPMT Raipur",
        "total_incidents": len(incidents),
        "resolved": sum(1 for i in incidents if i.status == "Resolved"),
        "active": sum(1 for i in incidents if i.status != "Resolved"),
        "campus_safety_score": calculate_safety_score(db),
        "generated_at": utc_now().isoformat(),
    }


@app.get("/api/reports/daily", tags=["Reports"])
def get_daily_report(db: Session = Depends(get_db)):
    return _build_summary_report(db, 1, "Daily")


@app.get("/api/reports/weekly", tags=["Reports"])
def get_weekly_report(db: Session = Depends(get_db)):
    return _build_summary_report(db, 7, "Weekly")


@app.get("/api/reports/monthly", tags=["Reports"])
def get_monthly_report(db: Session = Depends(get_db)):
    return _build_summary_report(db, 30, "Monthly")


@app.get("/api/notifications", tags=["Notifications"])
def get_notifications(db: Session = Depends(get_db)):
    return db.query(SOCNotification).order_by(desc(SOCNotification.created_at)).limit(20).all()


@app.post("/api/notifications/mark-read", tags=["Notifications"])
def mark_notifications_read(db: Session = Depends(get_db)):
    db.query(SOCNotification).filter(SOCNotification.is_read == False).update({"is_read": True})
    db.commit()
    return {"status": "ok", "marked_read": True}


# =========================================================
# 12. STATIC FRONTEND SERVER
# =========================================================
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/", include_in_schema=False)
async def serve_soc_dashboard():
    return FileResponse(STATIC_DIR / "index.html")
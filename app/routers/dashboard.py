from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.models.entities import Camera, Incident, IncidentStatus, Severity, CameraStatus
from app.dependencies import get_current_user
from app.services.safety import calculate_safety_score

router=APIRouter(prefix="/dashboard",tags=["Dashboard"])

@router.get("/overview")
def overview(db:Session=Depends(get_db),user=Depends(get_current_user)):
    since=datetime.now(timezone.utc)-timedelta(days=1)
    active=db.query(func.count(Incident.id)).filter(Incident.status.in_([IncidentStatus.open,IncidentStatus.acknowledged,IncidentStatus.investigating])).scalar()
    count=lambda event: db.query(func.count(Incident.id)).filter(Incident.event_type.ilike(f"%{event}%"),Incident.timestamp>=since).scalar()
    return {"total_cameras":db.query(func.count(Camera.id)).scalar(),
      "active_alerts":active,"intrusion_events":count("Unauthorized Entry"),"fall_detections":count("Fall"),
      "crowd_alerts":count("Crowd"),"campus_safety_score":calculate_safety_score(db),
      "system_status":"operational"}

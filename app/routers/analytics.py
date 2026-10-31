from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.models.entities import Incident, RiskZone
from app.dependencies import get_current_user

router=APIRouter(prefix="/analytics",tags=["Analytics"])

@router.get("/risk")
def risk(db:Session=Depends(get_db),user=Depends(get_current_user)):
    zones=db.query(RiskZone).all()
    return {z.name.lower().replace(" ","_"):{"score":z.score,"status":z.status,"active_cameras":z.active_cameras,"alerts_count":z.alerts_count} for z in zones}

@router.get("/trends")
def trends(db:Session=Depends(get_db),user=Depends(get_current_user)):
    days=[(datetime.now(timezone.utc)-timedelta(days=i)).date() for i in range(6,-1,-1)]
    rows=db.query(func.date(Incident.timestamp),Incident.event_type,func.count(Incident.id)).filter(
        Incident.timestamp>=datetime.now(timezone.utc)-timedelta(days=7)).group_by(func.date(Incident.timestamp),Incident.event_type).all()
    lookup={(str(d),e.lower()):n for d,e,n in rows}
    labels=[d.isoformat() for d in days]
    def series(term): return [sum(n for (d,e),n in lookup.items() if d==label and term in e) for label in labels]
    return {"labels":labels,"weekly_incidents":[sum(n for (d,e),n in lookup.items() if d==label) for label in labels],
            "crowd_alerts":series("crowd"),"intrusions":series("unauthorized"),"falls":series("fall"),
            "distribution":{"crowd":sum(series("crowd")),"intrusion":sum(series("unauthorized")),
                            "fall":sum(series("fall")),"abnormal_activity":sum(series("suspicious"))}}

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.entities import Incident
from app.dependencies import get_current_user

router=APIRouter(tags=["AI Insights"])

@router.get("/insights")
def insights(db:Session=Depends(get_db),user=Depends(get_current_user)):
    zones=db.query(Incident.location,func.count(Incident.id).label("total")).group_by(Incident.location).order_by(func.count(Incident.id).desc()).limit(3).all()
    results=[{"title":"Campus Activity Pattern","message":f"{location} has the highest recorded incident volume ({total} events). Review camera coverage and peak-hour staffing.","source":"incident_aggregation","confidence":"medium"} for location,total in zones]
    if not results: results=[{"title":"Monitoring Status","message":"No incident history is available yet. Insights will appear as verified events are recorded.","source":"system","confidence":"low"}]
    return results

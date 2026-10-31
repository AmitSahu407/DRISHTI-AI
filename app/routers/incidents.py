from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import Incident, Role
from app.schemas.api import IncidentCreate, IncidentUpdate, IncidentOut
from app.dependencies import get_current_user, require_roles
from app.services.audit import write_log
from app.services.notifications import create_dashboard_notification
from app.websocket import manager
from datetime import datetime, timezone

router=APIRouter(prefix="/incidents",tags=["Incidents"])

@router.get("",response_model=list[IncidentOut])
def list_incidents(skip:int=0,limit:int=50,severity:str|None=None,status:str|None=None,event_type:str|None=None,
                   db:Session=Depends(get_db),user=Depends(get_current_user)):
    q=db.query(Incident)
    if severity: q=q.filter(Incident.severity==severity)
    if status: q=q.filter(Incident.status==status)
    if event_type: q=q.filter(Incident.event_type.ilike(f"%{event_type}%"))
    return q.order_by(Incident.timestamp.desc()).offset(skip).limit(min(limit,200)).all()

@router.get("/{incident_id}",response_model=IncidentOut)
def get_incident(incident_id:int,db:Session=Depends(get_db),user=Depends(get_current_user)):
    obj=db.get(Incident,incident_id)
    if not obj: raise HTTPException(404,"Incident not found")
    return obj

@router.post("",response_model=IncidentOut,status_code=201)
async def create_incident(payload:IncidentCreate,request:Request,db:Session=Depends(get_db),user=Depends(require_roles(Role.super_admin,Role.security_admin,Role.security_officer))):
    obj=Incident(**payload.model_dump(),created_by_id=user.id)
    db.add(obj); db.flush()
    create_dashboard_notification(db,obj)
    write_log(db,"incident_created","incident",user.id,obj.id,{"event_type":obj.event_type})
    db.commit(); db.refresh(obj)
    await manager.broadcast({"event":obj.event_type.lower().replace(" ","_"),"incident_id":obj.id,
        "location":obj.location,"severity":obj.severity.value,"confidence":obj.confidence,
        "timestamp":obj.timestamp.isoformat(),"status":obj.status.value})
    return obj

@router.patch("/{incident_id}",response_model=IncidentOut)
def update_incident(incident_id:int,payload:IncidentUpdate,db:Session=Depends(get_db),user=Depends(require_roles(Role.super_admin,Role.security_admin,Role.security_officer))):
    obj=db.get(Incident,incident_id)
    if not obj: raise HTTPException(404,"Incident not found")
    for k,v in payload.model_dump(exclude_unset=True).items(): setattr(obj,k,v)
    write_log(db,"incident_updated","incident",user.id,obj.id,payload.model_dump(exclude_unset=True,mode="json"))
    db.commit(); db.refresh(obj); return obj

@router.delete("/{incident_id}",status_code=204)
def delete_incident(incident_id:int,db:Session=Depends(get_db),user=Depends(require_roles(Role.super_admin,Role.security_admin))):
    obj=db.get(Incident,incident_id)
    if not obj: raise HTTPException(404,"Incident not found")
    write_log(db,"incident_deleted","incident",user.id,obj.id); db.delete(obj); db.commit()

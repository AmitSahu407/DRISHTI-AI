from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import SystemLog, Role
from app.dependencies import require_roles

router=APIRouter(prefix="/logs",tags=["Audit Logs"])

@router.get("")
def list_logs(skip:int=0,limit:int=100,db:Session=Depends(get_db),user=Depends(require_roles(Role.super_admin,Role.security_admin))):
    rows=db.query(SystemLog).order_by(SystemLog.created_at.desc()).offset(skip).limit(min(limit,250)).all()
    return [{"id":x.id,"actor_id":x.actor_id,"action":x.action,"resource_type":x.resource_type,
             "resource_id":x.resource_id,"details":x.details,"ip_address":x.ip_address,"created_at":x.created_at} for x in rows]

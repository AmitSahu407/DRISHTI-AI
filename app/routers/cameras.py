from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import Camera, Role
from app.schemas.api import CameraIn, CameraOut
from app.dependencies import get_current_user, require_roles
from app.services.audit import write_log

router = APIRouter(prefix="/cameras", tags=["Cameras"])

@router.get("", response_model=list[CameraOut])
def list_cameras(skip: int=0, limit: int=100, db: Session=Depends(get_db), user=Depends(get_current_user)):
    return db.query(Camera).offset(skip).limit(min(limit, 200)).all()

@router.get("/{camera_id}", response_model=CameraOut)
def get_camera(camera_id: int, db: Session=Depends(get_db), user=Depends(get_current_user)):
    obj=db.get(Camera,camera_id)
    if not obj: raise HTTPException(404,"Camera not found")
    return obj

@router.post("", response_model=CameraOut, status_code=201)
def create_camera(payload: CameraIn, db: Session=Depends(get_db), user=Depends(require_roles(Role.super_admin,Role.security_admin))):
    obj=Camera(**payload.model_dump()); db.add(obj); db.flush()
    write_log(db,"camera_created","camera",user.id,obj.id)
    db.commit(); db.refresh(obj); return obj

@router.put("/{camera_id}", response_model=CameraOut)
def update_camera(camera_id:int,payload:CameraIn,db:Session=Depends(get_db),user=Depends(require_roles(Role.super_admin,Role.security_admin))):
    obj=db.get(Camera,camera_id)
    if not obj: raise HTTPException(404,"Camera not found")
    for k,v in payload.model_dump().items(): setattr(obj,k,v)
    write_log(db,"camera_updated","camera",user.id,obj.id); db.commit(); db.refresh(obj); return obj

@router.delete("/{camera_id}",status_code=204)
def delete_camera(camera_id:int,db:Session=Depends(get_db),user=Depends(require_roles(Role.super_admin,Role.security_admin))):
    obj=db.get(Camera,camera_id)
    if not obj: raise HTTPException(404,"Camera not found")
    write_log(db,"camera_deleted","camera",user.id,obj.id); db.delete(obj); db.commit()

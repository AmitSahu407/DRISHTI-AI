from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db
from app.dependencies import get_current_user
from app.models.entities import Camera, CameraStatus

router=APIRouter(prefix="/system",tags=["System"])

@router.get("/health")
def health(db:Session=Depends(get_db),user=Depends(get_current_user)):
    db.execute(text("SELECT 1"))
    total=db.query(Camera).count()
    online=db.query(Camera).filter(Camera.status==CameraStatus.online).count()
    connectivity=f"{round(online/total*100) if total else 0}%"
    return {"ai_engine":"simulated","camera_connectivity":connectivity,"detection_accuracy":"not_calibrated",
            "latency":"not_measured","database":"healthy","alerts":"websocket_process_local"}

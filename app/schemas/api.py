from pydantic import BaseModel, EmailStr, ConfigDict, Field
from typing import Optional, Any
from datetime import datetime
from app.models.entities import Role, CameraStatus, Severity, IncidentStatus

class UserCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: Role = Role.viewer

class UserOut(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: Role
    is_active: bool
    model_config = ConfigDict(from_attributes=True)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshIn(BaseModel):
    refresh_token: str

class CameraIn(BaseModel):
    camera_name: str = Field(min_length=2, max_length=120)
    location: str = Field(min_length=2, max_length=180)
    rtsp_url: Optional[str] = None
    status: CameraStatus = CameraStatus.offline
    risk_level: str = "safe"
    people_count: int = Field(default=0, ge=0)
    building_id: Optional[int] = None

class CameraOut(CameraIn):
    id: int
    last_activity: Optional[datetime]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class IncidentCreate(BaseModel):
    camera_id: Optional[int] = None
    event_type: str
    location: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    description: str
    snapshot_url: Optional[str] = None

class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[Severity] = None
    description: Optional[str] = None

class IncidentOut(BaseModel):
    id: int
    camera_id: Optional[int]
    event_type: str
    location: str
    severity: Severity
    confidence: float
    description: str
    status: IncidentStatus
    snapshot_url: Optional[str]
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)

class MessageOut(BaseModel):
    message: str

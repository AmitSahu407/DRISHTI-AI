from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from datetime import timedelta, datetime, timezone
from jose import JWTError
from app.database import get_db
from app.schemas.api import UserCreate, UserOut, LoginIn, TokenOut, RefreshIn
from app.models.entities import User, RefreshToken
from app.utils.security import hash_password, verify_password, create_token, decode_token
from app.config import settings
from app.dependencies import get_current_user
from app.services.audit import write_log

router = APIRouter(prefix="/auth", tags=["Authentication"])

def issue_tokens(db, user):
    access, _, _ = create_token(str(user.id), "access", timedelta(minutes=settings.access_token_expire_minutes))
    refresh, jti, exp = create_token(str(user.id), "refresh", timedelta(days=settings.refresh_token_expire_days))
    db.add(RefreshToken(user_id=user.id, token_jti=jti, expires_at=exp))
    return TokenOut(access_token=access, refresh_token=refresh)

@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(409, "Email already registered")
    # Public registration cannot grant elevated roles.
    user = User(full_name=payload.full_name, email=payload.email,
                password_hash=hash_password(payload.password), role="viewer")
    db.add(user); db.commit(); db.refresh(user)
    return user

@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    write_log(db, "login", "user", user.id, user.id, ip_address=request.client.host if request.client else None)
    tokens = issue_tokens(db, user); db.commit()
    return tokens

@router.post("/refresh", response_model=TokenOut)
def refresh(payload: RefreshIn, db: Session = Depends(get_db)):
    try:
        data = decode_token(payload.refresh_token)
        if data.get("type") != "refresh": raise ValueError()
        jti, user_id = data["jti"], int(data["sub"])
    except (JWTError, ValueError, KeyError, TypeError):
        raise HTTPException(401, "Invalid refresh token")
    record = db.query(RefreshToken).filter_by(token_jti=jti, user_id=user_id, revoked=False).first()
    if not record or record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Refresh token expired or revoked")
    record.revoked = True
    user = db.get(User, user_id)
    if not user or not user.is_active: raise HTTPException(401, "Inactive user")
    tokens = issue_tokens(db, user); db.commit()
    return tokens

@router.post("/logout")
def logout(payload: RefreshIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try: data = decode_token(payload.refresh_token)
    except JWTError: raise HTTPException(400, "Invalid refresh token")
    record = db.query(RefreshToken).filter_by(token_jti=data.get("jti"), user_id=user.id).first()
    if record: record.revoked = True; db.commit()
    return {"message": "Logged out"}

@router.get("/me", response_model=UserOut)
def me(user=Depends(get_current_user)):
    return user

"""
NO ENTRY - Authentication API & Session Management
Handles operator registration, bcrypt verification, PyJWT tokens, and httpOnly cookies.
"""

from datetime import datetime, timedelta
import secrets
from typing import Optional, Any
import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlmodel import Session, select

from backend.app.config import settings
from backend.app.db.database import get_session
from backend.app.db.models import User

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])

AUTH_COOKIE_NAME = "ne_auth_token"

class LoginRequest(BaseModel):
    operator_id: str
    passphrase: str

class OperatorResponse(BaseModel):
    id: int
    operator_id: str
    username: str
    role: str
    xp: int
    rank: str

def hash_password(password: str) -> str:
    """Hash passphrase using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify passphrase against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate signed PyJWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate PyJWT access token."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None

def get_current_user(
    request: Request,
    session: Session = Depends(get_session)
) -> User:
    """Dependency to retrieve currently authenticated operator."""
    token = request.cookies.get(AUTH_COOKIE_NAME)

    # Fallback to Authorization header if cookie not present
    if not token and "Authorization" in request.headers:
        auth_header = request.headers["Authorization"]
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. No session token provided."
        )

    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token invalid or expired."
        )

    operator_id = payload["sub"]
    statement = select(User).where(User.operator_id == operator_id)
    user = session.exec(statement).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Operator record not found."
        )

    return user


def resolve_operator(
    request: Optional[Any] = None,
    session: Session = Depends(get_session)
) -> User:
    """
    Resolve the authenticated operator from JWT cookie/header, or fall back to
    the local default operator ('op-0x7f3a') when browsing unauthenticated.
    Supports Request, WebSocket, or None.
    """
    token = None
    if request is not None and hasattr(request, "cookies"):
        token = request.cookies.get(AUTH_COOKIE_NAME)
        if not token and hasattr(request, "headers") and "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]

    if token:
        try:
            return get_current_user(request=request, session=session)
        except Exception:
            pass

    statement = select(User).where(User.operator_id == "op-0x7f3a")
    default_user = session.exec(statement).first()
    if not default_user:
        default_user = User(
            username="op-0x7f3a",
            operator_id="op-0x7f3a",
            hashed_password=hash_password(secrets.token_urlsafe(16)),
            role="operator",
            xp=1240,
            rank="SCRIPT RUNNER",
            ethics_accepted=False,
            streak_days=3,
        )
        session.add(default_user)
        session.commit()
        session.refresh(default_user)
    return default_user

@auth_router.post("/login", response_model=OperatorResponse)
def login(req: LoginRequest, response: Response, session: Session = Depends(get_session)):
    """
    Authenticate operator or automatically register on first encounter.
    Issues JWT inside an httpOnly cookie.
    """
    op_id = req.operator_id.strip()
    if not op_id or not req.passphrase.strip():
        raise HTTPException(status_code=400, detail="Operator ID and passphrase are required.")

    statement = select(User).where((User.operator_id == op_id) | (User.username == op_id))
    user = session.exec(statement).first()

    if not user:
        # Auto-registration on first login
        hashed = hash_password(req.passphrase)
        user = User(
            username=op_id,
            operator_id=op_id,
            hashed_password=hashed,
            role="operator",
            xp=1240,
            rank="SCRIPT RUNNER"
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    else:
        # Operator exists: verify passphrase
        if not verify_password(req.passphrase, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="ACCESS DENIED: invalid passphrase for operator"
            )

    token = create_access_token({"sub": user.operator_id, "role": user.role})
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False, # True if production HTTPS
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    return OperatorResponse(
        id=user.id,
        operator_id=user.operator_id,
        username=user.username,
        role=user.role,
        xp=user.xp,
        rank=user.rank
    )

@auth_router.post("/guest", response_model=OperatorResponse)
def login_guest(response: Response, session: Session = Depends(get_session)):
    """Authenticate or create a guest operator session."""
    guest_op_id = f"op-{secrets.token_hex(3)}"
    random_pass = secrets.token_urlsafe(16)

    user = User(
        username=guest_op_id,
        operator_id=guest_op_id,
        hashed_password=hash_password(random_pass),
        role="guest",
        xp=1000,
        rank="SCRIPT RUNNER"
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    token = create_access_token({"sub": user.operator_id, "role": user.role})
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    return OperatorResponse(
        id=user.id,
        operator_id=user.operator_id,
        username=user.username,
        role=user.role,
        xp=user.xp,
        rank=user.rank
    )

@auth_router.get("/me", response_model=OperatorResponse)
def get_me(user: User = Depends(get_current_user)):
    """Retrieve current operator profile."""
    return OperatorResponse(
        id=user.id,
        operator_id=user.operator_id,
        username=user.username,
        role=user.role,
        xp=user.xp,
        rank=user.rank
    )

@auth_router.post("/logout")
def logout(response: Response):
    """Terminate current operator session and clear auth cookie."""
    response.delete_cookie(key=AUTH_COOKIE_NAME)
    return {"status": "success", "message": "Operator logged out. Uplink severed."}

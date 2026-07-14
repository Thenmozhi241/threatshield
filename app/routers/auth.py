"""Authentication routes: register, login (API + HTML form), logout."""
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.schemas.auth import RegisterRequest, Token
from app.services import auth_service
from app.services.audit_service import log_action
from app.utils.security import create_access_token

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ---------- JSON API ----------

@router.post("/api/auth/register", response_model=Token, tags=["auth"])
def api_register(payload: RegisterRequest, db: Session = Depends(get_db)):
    try:
        user = auth_service.register_user(db, payload.username, payload.email, payload.password, payload.full_name)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    log_action(db, user.id, "register", resource=f"user:{user.id}")
    token = create_access_token(user.username)
    return Token(access_token=token)


@router.post("/api/auth/login", response_model=Token, tags=["auth"])
def api_login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = auth_service.authenticate_user(db, username, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    log_action(db, user.id, "login", resource=f"user:{user.id}")
    token = create_access_token(user.username, expires_delta=timedelta(minutes=settings.access_token_expire_minutes))
    return Token(access_token=token)


# ---------- HTML UI ----------

@router.get("/login", tags=["ui"])
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login", tags=["ui"])
def login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = auth_service.authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password"}, status_code=401
        )
    log_action(db, user.id, "login", resource=f"user:{user.id}")
    token = create_access_token(user.username)
    redirect = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(key="access_token", value=token, httponly=True, samesite="lax")
    return redirect


@router.get("/register", tags=["ui"])
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.post("/register", tags=["ui"])
def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    full_name: str = Form(""),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        user = auth_service.register_user(db, username, email, password, full_name)
    except ValueError as exc:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": str(exc)}, status_code=400
        )
    log_action(db, user.id, "register", resource=f"user:{user.id}")
    token = create_access_token(user.username)
    redirect = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(key="access_token", value=token, httponly=True, samesite="lax")
    return redirect


@router.get("/logout", tags=["ui"])
def logout():
    redirect = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    redirect.delete_cookie("access_token")
    return redirect

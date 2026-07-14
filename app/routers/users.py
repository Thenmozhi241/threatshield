"""User management routes (admin only): list, create, update, deactivate users."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status

from app.database import get_db
from app.dependencies import get_current_user, require_admin
from app.models.role import Role
from app.models.user import User
from app.schemas.user import UserCreateAdmin, UserOut, UserUpdate
from app.services.audit_service import log_action
from app.utils.security import hash_password

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/users", tags=["ui"])
def users_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    roles = db.query(Role).all()
    return templates.TemplateResponse("users.html", {"request": request, "user": user, "users": users, "roles": roles})


@router.post("/users/add", tags=["ui"])
def add_user_ui(
    username: str = Form(...),
    email: str = Form(...),
    full_name: str = Form(""),
    password: str = Form(...),
    role_id: int = Form(...),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    new_user = User(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role_id=role_id,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    log_action(db, admin.id, "create_user", resource=f"user:{new_user.id}")
    return RedirectResponse(url="/users", status_code=status.HTTP_302_FOUND)


@router.post("/users/{user_id}/toggle-active", tags=["ui"])
def toggle_active_ui(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_active = not target.is_active
    db.commit()
    log_action(db, admin.id, "toggle_user_active", resource=f"user:{user_id}")
    return RedirectResponse(url="/users", status_code=status.HTTP_302_FOUND)


@router.get("/profile", tags=["ui"])
def profile_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})


# ---------- JSON API ----------

@router.get("/api/users", response_model=list[UserOut], tags=["users"])
def api_list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(User).all()


@router.post("/api/users", response_model=UserOut, tags=["users"])
def api_create_user(payload: UserCreateAdmin, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    new_user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role_id=payload.role_id,
        is_superuser=payload.is_superuser,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    log_action(db, admin.id, "create_user", resource=f"user:{new_user.id}")
    return new_user


@router.patch("/api/users/{user_id}", response_model=UserOut, tags=["users"])
def api_update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    log_action(db, admin.id, "update_user", resource=f"user:{user_id}")
    return target

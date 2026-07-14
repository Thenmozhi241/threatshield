"""Authentication business logic: registration and login."""
from sqlalchemy.orm import Session

from app.models.role import Role
from app.models.user import User
from app.utils.security import hash_password, verify_password


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).first()


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email).first()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def register_user(db: Session, username: str, email: str, password: str, full_name: str | None = None) -> User:
    if get_user_by_username(db, username):
        raise ValueError("Username already registered")
    if get_user_by_email(db, email):
        raise ValueError("Email already registered")

    default_role = db.query(Role).filter(Role.name == "viewer").first()
    if not default_role:
        default_role = Role(name="viewer", description="Read-only access")
        db.add(default_role)
        db.commit()
        db.refresh(default_role)

    user = User(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role_id=default_role.id,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

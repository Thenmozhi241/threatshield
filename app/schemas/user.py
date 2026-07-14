from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: str | None = None
    is_active: bool
    is_superuser: bool
    role_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    full_name: str | None = None
    email: EmailStr | None = None
    is_active: bool | None = None
    role_id: int | None = None


class UserCreateAdmin(BaseModel):
    username: str
    email: EmailStr
    full_name: str | None = None
    password: str
    role_id: int
    is_superuser: bool = False

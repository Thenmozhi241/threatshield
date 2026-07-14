from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class Role(Base):
    """User roles for role-based access control (RBAC)."""

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)  # admin, analyst, viewer
    description = Column(String(255), nullable=True)

    users = relationship("User", back_populates="role")

    def __repr__(self) -> str:
        return f"<Role {self.name}>"

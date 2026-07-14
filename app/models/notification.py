from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class Notification(Base):
    """A delivered (or attempted) notification: email, Telegram, Slack, or in-app."""

    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    channel = Column(String(20), nullable=False)  # email, telegram, slack, in_app
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    delivery_status = Column(String(20), default="pending")  # pending, sent, failed
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="notifications")
    alert = relationship("Alert", back_populates="notifications")

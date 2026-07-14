"""
SQLAlchemy engine / session management.

Works with SQLite out of the box for local development, and PostgreSQL in
production via the DATABASE_URL environment variable.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a database session and closes it after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Used for local/dev bootstrap; production should use Alembic."""
    import app.models  # noqa: F401  (ensure all models are registered on Base)

    Base.metadata.create_all(bind=engine)

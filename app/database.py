from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import settings

# Safely read lowercase or uppercase database_url from settings
raw_url = getattr(settings, "database_url", None) or getattr(
    settings, "DATABASE_URL", "sqlite:///./drishti_ai.db"
)

# Automatically use local SQLite on Windows if .env still points to Docker host 'db'
if "@db" in str(raw_url) or str(raw_url).startswith("sqlite"):
    db_url = "sqlite:///./drishti_ai.db"
    is_sqlite = True
else:
    db_url = str(raw_url)
    is_sqlite = False

engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False} if is_sqlite else {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
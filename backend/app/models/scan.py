from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func

from app.database import Base


class Scan(Base):

    __tablename__ = "scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True
    )

    scan_type = Column(
        String(50),
        nullable=False
    )

    input_data = Column(
        Text,
        nullable=False
    )

    result = Column(
        String(50),
        nullable=False
    )

    risk_score = Column(
        Integer,
        nullable=False
    )

    explanation = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database.db import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50))        # s3, security_group, iam, encryption
    resource_id = Column(String(200))
    severity = Column(String(20))         # CRITICAL, HIGH, MEDIUM, LOW
    finding = Column(Text)
    recommendation = Column(Text)
    cis_benchmark = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
from sqlalchemy import Column, Integer, String, DateTime
from database import Base
import datetime

class LogEntry(Base):
    __tablename__ = "log_entries"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String, index=True)
    method = Column(String)
    path = Column(String)
    status = Column(Integer)

from sqlalchemy import Column, Integer, String, DateTime
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = 'tbl_user'

    user_Id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    fname = Column(String(255))
    email = Column(String(200), unique=True, index=True)
    phone = Column(String(50))
    hashed_password = Column(String(255))
    role_id = Column(Integer, default=3)
    device_id = Column(String(50), default='test')
    added_on = Column(DateTime, default=datetime.utcnow)
    isActive = Column(Integer, default=0)

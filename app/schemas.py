from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, DateTime

from app.db.config import Base


class UserBase(BaseModel):
    full_name: str
    email: EmailStr
    role: Optional[str] = "user"
    verified: Optional[bool] = False


class RegisterUserRequest(BaseModel):
    email: EmailStr
    password: str
    password_confirm: str


class UserUpdate(BaseModel):
    full_name: Optional[str]
    email: Optional[EmailStr]
    role: Optional[str]
    verified: Optional[bool]


class UserResponse(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    verified: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UsersResponse(BaseModel):
    data: List[UserResponse]
    total: int
    skip: int
    limit: int


# RefreshToken model
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    token = Column(String(255))
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

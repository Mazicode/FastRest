from datetime import datetime as dt
from typing import List, Optional, Union

from pydantic import BaseModel, constr, EmailStr
from pydantic.v1 import validator


class UserBaseSchema(BaseModel):
    full_name: Optional[str] = None
    email: str
    role: Optional[str] = None
    disabled: Union[bool, None] = None
    created_at: Optional[dt] = None
    updated_at: Optional[dt] = None

    class Config:
        from_attributes = True


class UserUpdateSchema(BaseModel):
    full_name: Optional[str] = ""
    email: Optional[str] = None
    role: Optional[str] = None

    @validator('email', pre=True, always=True)
    def check_email(self, value):
        if value == "":
            return value
        if value is not None:
            return EmailStr.validate(value)
        return value


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserResponseSchema(BaseModel):
    id: str
    full_name: Optional[str]
    email: EmailStr
    role: Optional[str]


class UserResponse(BaseModel):
    message: Optional[str] = None
    data: Optional[UserResponseSchema] = None


class UsersResponse(BaseModel):
    data: List[UserResponseSchema]
    total: int
    skip: int
    limit: int


class CreateUserSchema(UserBaseSchema):
    full_name: Optional[str] = None
    email: str
    password: constr(min_length=8)
    password_confirm: str
    verified: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str
    email: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class VerifyEmailResponse(BaseModel):
    status: str
    message: str

from datetime import datetime as dt
from typing import List, Optional, Union

from pydantic import BaseModel, constr, EmailStr


class UserBaseSchema(BaseModel):
    email: str
    disabled: Union[bool, None] = None
    created_at: Optional[dt] = None
    updated_at: Optional[dt] = None

    class Config:
        from_attributes = True


class UserUpdateSchema(BaseModel):
    name: Optional[str] = ""
    email: Optional[EmailStr] = None


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserResponseSchema(UserBaseSchema):
    id: str


class UserResponse(BaseModel):
    status: str
    user: UserResponseSchema


class UsersResponse(BaseModel):
    message: str
    users: List[UserResponse]
    total: int
    skip: int
    limit: int


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class FilteredUserResponse(UserBaseSchema):
    id: str


class UserInDB(UserBaseSchema):
    hashed_password: str


class CreateUserSchema(UserBaseSchema):
    full_name: Optional[str] = None
    email: str
    password: constr(min_length=8)
    password_confirm: str
    verified: bool = False

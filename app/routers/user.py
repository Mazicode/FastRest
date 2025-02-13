from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.orm import Session
from starlette import status

from app.db.config import get_db
from app.db.models import User
from app.responses import GET_USER_JSON, UPDATE_USER_JSON, FIND_USERS_JSON
from app.schemas import UserResponse, UserUpdate, UsersResponse

router = APIRouter()


@router.get('/{user_id}',
            response_model=UserResponse,
            response_description="Successful retrieval of a user's details.",
            summary="Retrieve a user's information",
            description="Fetches a user's details by their unique user ID. If the user is not found, returns a 404 "
                        "error.",
            responses=GET_USER_JSON
            )
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User {user_id} not found")

    return user


@router.put('/{user_id}',
            response_model=UserResponse,
            response_description="Successful update returns the updated user information. Deletion returns a success "
                                 "message.",
            summary="Update a user's information or delete the user",
            description="Allows partial updates to a user's information. If an empty string is provided for the email "
                        "field, the user will be deleted.",
            responses=UPDATE_USER_JSON
            )
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User {user_id} not found")

    # If email is an empty string, delete the user
    if payload.email == "":
        db.delete(user)
        db.commit()
        return {"message": "User successfully deleted"}

    # Update user fields
    update_data = payload.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)

    return user


@router.get('/',
            response_model=UsersResponse,
            response_description="Successful retrieval returns a list of users with pagination.",
            summary="Retrieve a list of users with optional filters and pagination",
            description="Fetches a list of users with optional filters for name, email, and role, with pagination "
                        "support.",
            responses=FIND_USERS_JSON
            )
def find_users(
        db: Session = Depends(get_db),
        full_name: Optional[str] = Query(None, description="Filter by user's full name"),
        email: Optional[str] = Query(None, description="Filter by user's email"),
        role: Optional[str] = Query(None, description="Filter by user's role"),
        skip: int = Query(0, description="Number of users to skip"),
        limit: int = Query(10, description="Maximum number of users to return")
):
    query = db.query(User)

    if full_name:
        query = query.filter(User.full_name.like(f"%{full_name}%"))
    if email:
        query = query.filter(User.email.like(f"%{email}%"))
    if role:
        query = query.filter(User.role == role)

    total_users = query.count()
    users = query.offset(skip).limit(limit).all()

    return {"data": users, "total": total_users, "skip": skip, "limit": limit}

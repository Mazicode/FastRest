import os
from typing import Optional
from venv import logger

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query, Depends
from jwt import ExpiredSignatureError, InvalidTokenError
from starlette import status
from starlette.responses import JSONResponse

from app import schemas
from app.routers.auth import oauth2_scheme, is_denied
from app.db import Users
from app.schemas import UserUpdateSchema, UserResponseSchema, UserResponse
from app.serializers.user import get_serialized_user_response

router = APIRouter()

@router.get('/{user_id}',
            response_model=schemas.UserResponse,
            summary="Retrieve a user's information",
            description="Fetches a user's details by their unique user ID. If the user is not found, returns a 404 "
                        "error.",
            response_description="Successful retrieval returns the user's details.",
            responses={
                status.HTTP_200_OK: {
                    "description": "User retrieved successfully.",
                    "content": {
                        "application/json": {
                            "example": {
                                "message": "success",
                                "data": {
                                    "_id": "user_id",
                                    "name": "User Name",
                                    "email": "user_email@example.com",
                                    "role": "user",
                                    "verified": False,
                                    "created_at": "2021-01-01T00:00:00Z",
                                    "updated_at": "2021-01-01T00:00:00Z"
                                }
                            }
                        }
                    }
                },
                status.HTTP_404_NOT_FOUND: {
                    "description": "User not found.",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "User user_id not found"
                            }
                        }
                    }
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR: {
                    "description": "Internal server error.",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "An unexpected error occurred"
                            }
                        }
                    }
                }
            })
def get_user(user_id: str, token: str = Depends(oauth2_scheme)):
    unauthorized = is_denied(token)
    if unauthorized:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Find the user by ID
        user_doc = Users.find_one({'_id': ObjectId(user_id)})
        if user_doc is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User {user_id} not found")

        # Convert user_doc to response schema
        user_response = UserResponseSchema(
            id=str(user_doc['_id']),
            full_name=user_doc.get('full_name'),
            email=user_doc.get('email'),
            role=user_doc.get('role')
        )
        return {"message": "success", "data": user_response}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")


@router.put('/{user_id}',
            response_model=UserResponse,
            summary="Updates a user's information or deletes the user.",
            description="Allows partial updates to a user's information. If an empty string is provided for the "
                        "email field, the user will be deleted.",
            response_description="Successful update returns the updated user information. If the user is deleted, "
                                 "the response will indicate successful deletion.",
            responses={
                status.HTTP_200_OK: {
                    "description": "User updated successfully or user successfully deleted.",
                    "content": {
                        "application/json": {
                            "examples": {
                                "Update Success": {
                                    "summary": "User updated successfully.",
                                    "value": {
                                        "message": "success",
                                        "user": {
                                            "id": "user_id",
                                            "name": "Updated Name",
                                            "email": "updated_email@example.com",
                                            "role": "user",
                                            "verified": False,
                                            "created_at": "2021-01-01T00:00:00Z",
                                            "updated_at": "2021-01-01T00:00:00Z"
                                        }
                                    }
                                },
                                "Delete Success": {
                                    "summary": "User successfully deleted.",
                                    "value": {
                                        "message": "User successfully deleted"
                                    }
                                }
                            }
                        }
                    }
                },
                status.HTTP_403_FORBIDDEN: {
                    "description": "Operation not allowed.",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "Operation not allowed"
                            }
                        }
                    }
                },
                status.HTTP_404_NOT_FOUND: {
                    "description": "User not found.",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "User user_id not found"
                            }
                        }
                    }
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR: {
                    "description": "Internal server error.",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "An unexpected error occurred"
                            }
                        }
                    }
                }
            })
async def update_user(user_id: str, payload: UserUpdateSchema, token=Depends(is_denied)):
    unauthorized = is_denied(token)
    if unauthorized:
        raise unauthorized

    try:
        user_object_id = ObjectId(user_id)
    except Exception as e:
        logger.error(f"Invalid user ID format: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format")

    try:
        # Check if "role" is in the payload and deny if it's not "admin"
        if payload.role and payload.role.lower() != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation not allowed")

        # Find the user by ID
        user_doc = Users.find_one({"_id": user_object_id})
        if user_doc is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User {user_id} not found")

        # Check if email is an empty string and handle deletion
        if payload.email == "":
            Users.delete_one({'_id': user_object_id})
            return JSONResponse(
                content={
                    "message": "User successfully deleted",
                    "data": {"id": user_id, "email": user_doc['email']}
                },
                status_code=status.HTTP_200_OK
            )

        # Prepare the update data
        update_data = {k: v for k, v in payload.dict().items() if v is not None}

        # Update the user in the database
        if update_data:
            Users.find_one_and_update(
                {"_id": user_object_id},
                {"$set": update_data}
            )

        # Retrieve the updated user document
        updated_user_doc = Users.find_one({'_id': user_object_id})

        # Convert database document to response schema
        updated_user_response = get_serialized_user_response(updated_user_doc)
        return JSONResponse(
            content={
                "message": "User successfully updated",
                "data": updated_user_response
            },
            status_code=status.HTTP_200_OK
        )

    except HTTPException as e:
        logger.error(f"HTTP exception occurred: {e.detail}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")


@router.get('/',
            response_model=schemas.UsersResponse,  # Create a new response schema for multiple users
            summary="Find users with optional filters and pagination",
            description="Fetches a list of users with optional filters for name, email, and role, with pagination "
                        "support.",
            response_description="Successful retrieval returns a list of users.",
            responses={
                status.HTTP_200_OK: {
                    "description": "Users retrieved successfully.",
                    "content": {
                        "application/json": {
                            "example": {
                                "message": "success",
                                "users": [
                                    {
                                        "_id": "user_id",
                                        "name": "User Name",
                                        "email": "user_email@example.com",
                                        "role": "user",
                                        "verified": False,
                                        "created_at": "2021-01-01T00:00:00Z",
                                        "updated_at": "2021-01-01T00:00:00Z"
                                    }
                                ],
                                "total": 1,
                                "skip": 0,
                                "limit": 10
                            }
                        }
                    }
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR: {
                    "description": "Internal server error.",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "An unexpected error occurred"
                            }
                        }
                    }
                }
            })
def find_users(
        token=Depends(is_denied),
        full_name: Optional[str] = Query(None, description="Filter by user's full name"),
        email: Optional[str] = Query(None, description="Filter by user's email"),
        role: Optional[str] = Query(None, description="Filter by user's role"),
        skip: int = Query(0, description="Number of users to skip"),
        limit: int = Query(10, description="Maximum number of users to return"),
):
    unauthorized = is_denied(token)
    if unauthorized:
        raise unauthorized

    try:
        # Build query filters
        filters = {}
        if full_name:
            filters['full_name'] = {"$regex": full_name, "$options": "i"}  # Case insensitive search
        if email:
            filters['email'] = {"$regex": email, "$options": "i"}  # Case insensitive search
        if role:
            filters['role'] = role

        # Find users with filters, skip, and limit
        users_cursor = Users.find(filters).skip(skip).limit(limit)
        users_list = list(users_cursor)

        # Assuming get_serialized_user_response is a function to convert database document to response schema
        users_response = [get_serialized_user_response(user_doc) for user_doc in users_list]

        # Total count of users matching the filters
        total_users = Users.count_documents(filters)
        # import pdb; pdb.set_trace()
        return {"data": users_response, "total": total_users, "skip": skip, "limit": limit}

    except Exception as e:
        # Handle any other exceptions
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

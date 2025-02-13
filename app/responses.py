from starlette import status

SIGNUP_JSON = {
    status.HTTP_201_CREATED: {
        "description": "User registered successfully and verification email sent.",
        "content": {
            "application/json": {
                "example": {
                    "status": "success",
                    "message": "Verification token successfully sent to your email"
                }
            }
        }
    },
    status.HTTP_400_BAD_REQUEST: {
        "description": "Validation error for provided input.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "Passwords do not match"
                }
            }
        }
    },
    status.HTTP_409_CONFLICT: {
        "description": "Conflict error when trying to register with an existing email.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "Account already exists"
                }
            }
        }
    },
    status.HTTP_500_INTERNAL_SERVER_ERROR: {
        "description": "Server error if something goes wrong during email sending.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "An unexpected error occurred"
                }
            }
        }
    }
}

LOGIN_JSON = {
    200: {"description": "Successful login",
          "content": {"application/json": {"example": {"status": "success", "access_token": "your_access_token"}}}},
    400: {"description": "Incorrect Email or Password",
          "content": {"application/json": {"example": {"detail": "Incorrect Email or Password"}}}},
    401: {"description": "Please verify your email address",
          "content": {"application/json": {"example": {"detail": "Please verify your email address"}}}}
}

GET_USER_JSON = {
    200: {
        "description": "User retrieved successfully.",
        "content": {
            "application/json": {
                "example": {
                    "id": 1,
                    "full_name": "John Doe",
                    "email": "johndoe@example.com",
                    "role": "user",
                    "verified": False,
                    "created_at": "2021-01-01T00:00:00Z",
                    "updated_at": "2021-01-01T00:00:00Z"
                }
            }
        }
    },
    404: {
        "description": "User not found.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "User 1 not found"
                }
            }
        }
    },
    500: {
        "description": "Internal server error.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "An unexpected error occurred"
                }
            }
        }
    }
}

UPDATE_USER_JSON = {
    200: {
        "description": "User updated successfully or user deleted.",
        "content": {
            "application/json": {
                "examples": {
                    "Update Success": {
                        "summary": "User updated successfully.",
                        "value": {
                            "id": 1,
                            "full_name": "Jane Doe",
                            "email": "janedoe@example.com",
                            "role": "user",
                            "verified": True,
                            "created_at": "2021-01-01T00:00:00Z",
                            "updated_at": "2021-06-01T00:00:00Z"
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
    403: {
        "description": "Operation not allowed.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "Operation not allowed"
                }
            }
        }
    },
    404: {
        "description": "User not found.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "User 1 not found"
                }
            }
        }
    },
    500: {
        "description": "Internal server error.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "An unexpected error occurred"
                }
            }
        }
    }
}

FIND_USERS_JSON = {
    200: {
        "description": "Users retrieved successfully.",
        "content": {
            "application/json": {
                "example": {
                    "data": [
                        {
                            "id": 1,
                            "full_name": "John Doe",
                            "email": "johndoe@example.com",
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
    500: {
        "description": "Internal server error.",
        "content": {
            "application/json": {
                "example": {
                    "detail": "An unexpected error occurred"
                }
            }
        }
    }
}

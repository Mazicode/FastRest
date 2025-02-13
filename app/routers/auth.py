from fastapi import Response, Depends

from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from starlette import status

from app.config import settings
from app.db.config import get_db
from app.db.models import User
from app.responses import SIGNUP_JSON, LOGIN_JSON
from app.schemas import RefreshToken, RegisterUserRequest
from app.utils import hash_password, create_access_token, create_refresh_token, verify_password, verify_token, \
    validate_password

router = APIRouter()


@router.post('/signup',
             status_code=status.HTTP_201_CREATED,
             summary="Register a new user",
             description="Registers a new user by creating a new user entry in the database. Validates the user "
                         "input, hashes the password, and sends a verification email to the user with a verification "
                         "token. If an error occurs during email sending, the verification code is cleaned up.",
             response_description="Successful registration returns a status message indicating that a verification "
                                  "token was sent to the user's email.",
             responses=SIGNUP_JSON)
def register_user(user_data: RegisterUserRequest, db: Session = Depends(get_db)):
    # Check if user already exists
    user = db.query(User).filter(User.email == user_data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Validate passwords
    validate_password(user_data.password, user_data.password_confirm)

    # Hash password and create a new user
    hashed_password = hash_password(user_data.password)
    new_user = User(email=user_data.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}


@router.post('/login', summary="Login User", response_description="Access and refresh tokens",
             responses=LOGIN_JSON)
def login(email: str, password: str, db: Session = Depends(get_db), response: Response = None):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token(data={"email": user.email})
    refresh_token = create_refresh_token(data={"email": user.email})

    db_token = RefreshToken(user_id=user.id, token=refresh_token, expires_at=settings.REFRESH_TOKEN_EXPIRES_IN)
    db.add(db_token)
    db.commit()

    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True)

    return {"access_token": access_token}


@router.post("/refresh_token")
def refresh_token(db: Session = Depends(get_db), token: str = Depends(verify_token)):
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    email = db_token.user.email

    new_access_token = create_access_token(data={"email": email})

    return {"access_token": new_access_token}

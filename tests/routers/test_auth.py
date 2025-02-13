import pytest

from app.db import get_db, Base
from app.db.models import User
from app.schemas import RefreshToken
from app.utils import hash_password, create_refresh_token
from tests.config import engine, setup_database, clear_database, client


@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown():
    """ Fixture to set up and tear down the test database """
    # Create all the tables
    Base.metadata.create_all(bind=engine)

    # Teardown logic after all tests
    yield
    Base.metadata.drop_all(bind=engine)


class TestAuthEndpoints:

    @setup_database()
    @clear_database()
    def test_signup_valid(self):
        """Test user registration with valid data"""
        response = client.post('/signup', json={"email": "test@example.com", "password": "strongpassword"})
        assert response.status_code == 201
        assert response.json() == {"message": "User created successfully"}

        # Check if the user was added to the database
        with client.app.dependency_overrides[get_db]() as db:
            user = db.query(User).filter(User.email == "test@example.com").first()
            assert user is not None
            assert user.email == "test@example.com"

    @setup_database()
    @clear_database()
    def test_signup_existing_email(self):
        """Test user registration with an existing email"""
        # Add a user to the test DB manually
        existing_user = User(email="test@example.com", hashed_password=hash_password("password"))
        with client.app.dependency_overrides[get_db]() as db:
            db.add(existing_user)
            db.commit()

        response = client.post('/signup', json={"email": "test@example.com", "password": "newpassword"})
        assert response.status_code == 400
        assert response.json() == {"detail": "Email already registered"}

    @setup_database()
    @clear_database()
    def test_login_valid(self):
        """Test user login with valid credentials"""
        # Add a user to the test DB manually
        user = User(email="login@example.com", hashed_password=hash_password("password"))
        with client.app.dependency_overrides[get_db]() as db:
            db.add(user)
            db.commit()

        response = client.post('/login', json={"email": "login@example.com", "password": "password"})
        assert response.status_code == 200
        tokens = response.json()
        assert "access_token" in tokens
        assert response.cookies.get("access_token") is not None
        assert response.cookies.get("refresh_token") is not None

    @setup_database()
    @clear_database()
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = client.post('/login', json={"email": "invalid@example.com", "password": "wrongpassword"})
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid email or password"}

    @setup_database()
    @clear_database()
    def test_refresh_token_valid(self):
        """Test refreshing access token with valid refresh token"""
        # Add a user and refresh token to the test DB manually
        user = User(email="refresh@example.com", hashed_password=hash_password("password"))
        with client.app.dependency_overrides[get_db]() as db:
            db.add(user)
            db.commit()

            refresh_token = create_refresh_token(data={"email": user.email})
            db_refresh_token = RefreshToken(user_id=user.id, token=refresh_token)
            db.add(db_refresh_token)
            db.commit()

        # Mock the dependency to return the valid refresh token
        response = client.post("/refresh_token", json={"token": refresh_token})
        assert response.status_code == 200
        new_access_token = response.json()["access_token"]
        assert new_access_token is not None

    @setup_database()
    @clear_database()
    def test_refresh_token_invalid(self):
        """Test refreshing access token with invalid refresh token"""
        response = client.post("/refresh_token", json={"token": "invalid_token"})
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid refresh token"}

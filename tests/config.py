from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import get_db
from app.main import api
from app.db.models import User, Base
from app.schemas import RefreshToken

SQLALCHEMY_DATABASE_URL = "mysql+pymysql://username:password@localhost:3306/test_db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

client = TestClient(api)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def setup_database():
    def decorator(test_func):
        def wrapper(*args, **kwargs):
            # Create all tables in the test database
            Base.metadata.create_all(bind=engine)
            try:
                result = test_func(*args, **kwargs)
            finally:
                # Drop all tables after tests are done
                Base.metadata.drop_all(bind=engine)
            return result

        return wrapper

    return decorator


def clear_database():
    """Decorator to clear tables after each test."""

    def decorator(test_func):
        def wrapper(*args, **kwargs):
            # Clear data in User and RefreshToken tables
            with TestingSessionLocal() as session:
                session.query(User).delete()
                session.query(RefreshToken).delete()
                session.commit()
            return test_func(*args, **kwargs)

        return wrapper

    return decorator


api.dependency_overrides[get_db] = override_get_db


def method_name():
    def decorator(input_func):
        def wrapper(*args, **kwargs):
            return input_func(*args, **kwargs)

        return wrapper()

    return decorator

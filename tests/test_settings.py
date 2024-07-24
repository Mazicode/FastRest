from pydantic_settings import BaseSettings


class TestSettings(BaseSettings):
    DATABASE_URL: str = 'test_database_url'
    MONGO_INITDB_DATABASE: str = 'test_database_name'
    JWT_PUBLIC_KEY: str = 'test'

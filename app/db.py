import pymongo
from pymongo import mongo_client
from app.config import settings

client = mongo_client.MongoClient(settings.DATABASE_URL)
db = client[settings.MONGO_INITDB_DATABASE]
Users = db['users']
Users.create_index([("email", pymongo.ASCENDING)], unique=True)


async def check_user_exists(email: str) -> bool:
    user = Users.find_one({'email': email.lower()})

    return user is not None


from typing import Optional
from pydantic import BaseModel
import datetime as dt


# Define the Pydantic model for user data
class UserBaseSchema(BaseModel):
    email: str
    disabled: Optional[bool] = None
    created_at: Optional[dt.datetime] = None
    updated_at: Optional[dt.datetime] = None

    class Config:
        from_attributes = True

# Usage example

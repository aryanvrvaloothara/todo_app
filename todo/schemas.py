from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Activity(BaseModel):
    title: str
    description: str
    category: str
    due_date: datetime
    user_id: int


    class Config:
        orm_mode = True


class ReadActivity(Activity):
    id: int

    class Config:
        orm_mode = True


class UpdateActivity(BaseModel):
    title: str
    description: str
    category: str
    due_date: datetime


    class Config:
        orm_mode = True



class User(BaseModel):
    name: str
    email: str
    password: str

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str]


class UserLogin(BaseModel):
    email: str
    password: str

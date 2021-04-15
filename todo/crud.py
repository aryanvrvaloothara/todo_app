from datetime import timedelta, datetime
from typing import Optional

from fastapi import HTTPException
from fastapi.params import Depends
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import JSONResponse

import models
import schemas
from db import SessionLocal

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN_EXPIRE_MINUTES = 60

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

ALGORITHM = "HS256"

#-----------region auth --------


#-----------end region auth----------


#-------------region user------------------

def get_password_hash(password):
    try:
        return pwd_context.hash(password)
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail={"message": "Unexpected error occurred"})


def check_user(email: str, db):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.User):
    try:
        db_user = models.User(name=user.name, email=user.email,
                              password=get_password_hash(user.password))
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

    except Exception as e:
        print(e)
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unexpected Error Occurred")


#-------------end region user------------------


#------------region login------------
def verifyPassword(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail={"message": "Unexpected Error Occurred"})


def authenticateUser(db, email: str, password: str):
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            return False
        if not verifyPassword(password, user.password):
            return False
        return user
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail={"message": "Unexpected Error Occurred"})


def createAccessToken(data: dict, expires_delta: Optional[timedelta] = None):
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail={"message": "Unexpected Error Occured"})


def validateUser(userObj: models.User):
    if not userObj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid credentials"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        try:
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = createAccessToken(
                data={"sub": userObj.email}, expires_delta=access_token_expires
            )

            headers = {
                "access_token": access_token,
                "token_type": "bearer",
            }
            return JSONResponse(status_code=200, content=headers)
        except Exception as e:
            print(e)
            raise HTTPException(status_code=400, detail={"message": "Login Failed"})
#------------end region login-------------


#-----------region activity-----------------
def create_activity(db: Session, activity: schemas.Activity):
    try:
        db_activity = models.Activity(title=activity.title, description=activity.description,
                                      category=activity.category, due_date=activity.due_date,
                                      user_id=activity.user_id)
        db.add(db_activity)
        db.commit()
        db.refresh(db_activity)
        return db_activity

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unexpected Error Occurred")


def get_activities(db: Session, skip: int = 0, limit: int = 100):
    try:
        return db.query(models.Activity).offset(skip).limit(limit).all()
    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unexpected Error Occurred")


def get_activity(db: Session, id: int):
    # status_code = 0
    # detail = ""
    try:
        db_job = db.query(models.Activity).filter(models.Activity.id == id).first()
        if db_job is None:
            status_code=status.HTTP_404_NOT_FOUND
            detail="Activity not found"
        else:
            return db_job

    except Exception as e:
        print(e)
        status_code=status.HTTP_400_BAD_REQUEST
        detail="Unexpected Error Occurred"

    raise HTTPException(status_code=status_code, detail=detail)


def update_activity(db: Session, activity: schemas.UpdateActivity, id: int):
    try:
        db_activity = db.query(models.Activity).filter(models.Activity.id ==id).first()

        db_activity.title = activity.title
        db_activity.description = activity.description
        db_activity.category = activity.category
        db_activity.due_date = activity.due_date

        db.commit()
        db.refresh(db_activity)
        return db_activity

    except Exception as e:
        print(e)
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unexpected Error Occurred")


def delete_activity(db: Session, id: int):
    try:
        db.query(models.Activity).filter(models.Activity.id == id).delete(synchronize_session=False)
        db.commit()
        return None

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unexpected Error Occurred")


def find_activity(db: Session, search: str):
    try:
        result = db.query(models.Activity).filter(
            func.lower(models.Activity.title).like('%' + search + '%')
            | func.lower(models.Activity.category).like('%' + search + '%')
        ).all()
        return result

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unexpected Error Occurred")


#-----------end region activity-----------------
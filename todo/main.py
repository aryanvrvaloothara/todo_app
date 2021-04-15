from typing import List

from fastapi import FastAPI, Depends, HTTPException
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from starlette import status

import crud
import models
import schemas
from db import SessionLocal

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#-------------auth region----------

from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_user(db: Session, email: str):
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        if user:
            return user
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail={"message": "Common Unexpected Error"})


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, crud.SECRET_KEY, algorithms=[crud.ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise credentials_exception
            token_data = schemas.TokenData(email=email)
        except JWTError:
            raise credentials_exception
        user = get_user(db=db, email=token_data.email)
        if user is None:
            raise credentials_exception
        return user
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail={"message": "Invalid Credentials"})


async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    print(1)
    try:
        return current_user
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail={"message": "Invalid Credentials"})
#-------------end auth region----------



#-------------user region----------
@app.post("/user/signup/", status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.User, db: Session = Depends(get_db)):
    is_user = crud.check_user(user.email, db)
    if is_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.post("/user/login", response_model=schemas.Token)
async def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    userObj = crud.authenticateUser(db, email=user.email, password=user.password)
    return crud.validateUser(userObj)
#-------------user region----------



#-------------activity region-----------------
@app.post("/activity/", status_code=status.HTTP_201_CREATED)
def create_activity(activity: schemas.Activity, db: Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_active_user)):
    return crud.create_activity(db=db, activity=activity)


@app.get("/activity/", response_model=List[schemas.ReadActivity])
def read_activities(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_active_user)):
    return crud.get_activities(db, skip=skip, limit=limit)


@app.get("/activity/{id}", response_model=schemas.ReadActivity)
def read_activitiy(id: int, db: Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_active_user)):
    return crud.get_activity(db, id=id)


@app.put("/activity/{id}")
def update_activity(activity: schemas.UpdateActivity, id: int, db: Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_active_user)):
    return crud.update_activity(db=db, activity=activity, id=id)


@app.delete("/activity/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_activity(id: int, db: Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_active_user)):
    return crud.delete_activity(db=db, id=id)


@app.get("/activity/search/{search}", response_model=List[schemas.ReadActivity])
def find_activity(search: str, db: Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_active_user)):
    return crud.find_activity(db=db, search=search)

#-------------end of activity region-----------------
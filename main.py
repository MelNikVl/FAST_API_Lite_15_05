from typing import Annotated, Optional
from jose import jwt, JWTError
from fastapi import FastAPI, Depends, HTTPException, File
from jwt import exceptions
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.context import CryptContext
from starlette import status
import time

app = FastAPI()

SECRET_KEY = "4545587fd8s7f8sd8f7ds8f78ds78f78ds7f8ds7"
ALGORITHM = 'HS256'

outh2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

engine = create_engine('sqlite:///materials.db', echo=False)
Session = sessionmaker(engine)
db = Session()
Base = declarative_base()


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    hash_password = Column(String)
    role = Column(String, nullable=True)
    email = Column(String)


class Materials(Base):
    __tablename__ = "materials"

    id = Column(Integer, primary_key=True)
    material_title = Column(String)
    material_description = Column(String)
    owner_id = Column(String, ForeignKey("users.id"))


Base.metadata.create_all(bind=engine)


def get_db():
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


class LoginForm(BaseModel):
    username: str
    password: str
    role: str
    email: str = Field(None, description="Optional email address")


def create_access_token(username: str,
                        user_id: int,
                        role: str):
    post_jwt = {'sub': username,
                'id': user_id,
                'role': role}
    return jwt.encode(post_jwt, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt(token: Annotated[str, Depends(outh2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("id")
        user_role: str = payload.get("role")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return {"username": username, "id": user_id, "role": user_role}
    except:
        return "токен не расшифрован"


user_dependency = Annotated[dict, Depends(decode_jwt)]


@app.post("/files")
async def UploadImage(file: bytes = File(...)):
    with open('image.jpg','wb') as image:
        image.write(file)
        image.close()
    return 'got it'


@app.post('/create_user')
async def create_user(db: db_dependency,
                      login_form: LoginForm):
    new_user = Users(name=login_form.username,
                     hash_password=bcrypt_context.hash(login_form.password),
                     role=login_form.role,
                     email=login_form.email
                     )
    db.add(new_user)
    db.commit()

    return f'пользователь {login_form.username} создан'


@app.get('/get_users')
async def get_users(user: user_dependency,
                    db: db_dependency):
    return db.query(Users).all()


@app.delete('/delete_users')
async def delete_user(user: user_dependency):
    db.query(Users).delete()
    db.commit()

    return "пользователи удалены"


@app.post('/token')
async def get_users(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    try:
        user_db = db.query(Users).filter(Users.name == form_data.username).first()
        cretated_token = create_access_token(form_data.username,
                                             user_db.role,
                                             user_db.id)
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not valiable user')

    return {'access_token': cretated_token, 'type_token': 'bearer'}

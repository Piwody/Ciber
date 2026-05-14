import os
from fastapi import FastAPI, HTTPException, status
from sqlmodel import SQLModel, Field, Session, create_engine, select
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
PEPPER = os.getenv("PEPPER")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str

class CrearUsusario(BaseModel):
    username: str
    password: str

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, echo=False)

def basetablas_modelo():
    SQLModel.metadata.create_all(engine)

app = FastAPI(title="Api")

@app.on_event("startup")
def on_startup():
    basetablas_modelo() 


def contrahash(password: str) -> str:
    peppered_password = password + PEPPER
    return pwd_context.hash(peppered_password)

def verificarcontra(plain_password: str, hashed_password: str) -> bool:
    peppered_password = plain_password + PEPPER
    return pwd_context.verify(peppered_password, hashed_password)


@app.post("/registro", status_code=status.HTTP_201_CREATED)
def register_user(user: CrearUsusario):  
    with Session(engine) as session:
        existing_user = session.exec(select(User).where(User.username == user.username)).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Ya existe")
        
        hashed_pw = contrahash(user.password)  
        db_user = User(username=user.username, hashed_password=hashed_pw)
        
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return {"message": "Registrado exitosamente", "user_id": db_user.id}

@app.post("/Inico")
def login_user(user: CrearUsusario): 
    with Session(engine) as session:
        db_user = session.exec(select(User).where(User.username == user.username)).first()
        
        if not db_user:
            raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectas")
        
        if not verificarcontra(user.password, db_user.hashed_password): 
            raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectas")
            
        return {"message": "Autenticación exitosa", "username": db_user.username} 
        
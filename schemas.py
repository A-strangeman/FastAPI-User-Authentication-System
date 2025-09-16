from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    fname: str
    email: EmailStr
    password: str
    phone: str
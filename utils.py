from passlib.context import CryptContext
from jose import jwt
import smtplib
import os

SECRET_KEY = os.getenv("SECRET_KEY", "SECRET_KEY_SAMPLE")
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def send_reset_email(email: str, token: str):
    with smtplib.SMTP('smtp.example.com', 587) as smtp:
        smtp.starttls()
        smtp.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
        message = f"Subject: Password Reset\n\nUse this token to reset your password: {token}"
        smtp.sendmail('from@example.com', email, message)
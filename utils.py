import os
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load secret key and algorithm from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "SECRET_KEY_SAMPLE")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return email
    except JWTError:
        return None

def send_reset_email(email: str, token: str):
    try:
        # Gmail SMTP configuration
        smtp_host = "smtp.gmail.com"
        smtp_port = 587

        smtp_user = os.getenv("EMAIL_USER")      # Your Gmail address
        smtp_pass = os.getenv("EMAIL_PASS")      # Gmail App Password (not regular password)

        if not smtp_user or not smtp_pass:
            raise Exception("EMAIL_USER and EMAIL_PASS must be set in .env file")

        # Create message
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = email
        msg['Subject'] = "Password Reset Request"

        # Reset URL (adjust this to your frontend URL)
        reset_url = f"http://localhost:3000/reset-password?token={token}"
        
        # Email body
        body = f"""
        Hello,

        You requested a password reset for your account.

        Click the link below to reset your password:
        {reset_url}

        Or use this token directly: {token}

        This link will expire in 30 minutes.

        If you didn't request this reset, please ignore this email.

        Best regards,
        Your App Team
        """

        msg.attach(MIMEText(body, 'plain'))

        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()  # Enable TLS encryption
            server.login(smtp_user, smtp_pass)
            text = msg.as_string()
            server.sendmail(smtp_user, email, text)
            
        logger.info(f"Password reset email sent successfully to {email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email to {email}: {str(e)}")
        raise Exception(f"Failed to send reset email: {str(e)}")
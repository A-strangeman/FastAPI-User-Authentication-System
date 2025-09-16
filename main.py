from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User
from schemas import UserCreate
from utils import (
    get_password_hash, 
    verify_password, 
    create_access_token, 
    send_reset_email,
    verify_token
)
from dotenv import load_dotenv
from datetime import timedelta
import logging
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Authentication API", version="1.0.0")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"message": "Authentication API is running"}

@app.post('/signup')
def signup(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        new_user = User(
            fname=user.fname,
            email=user.email,
            phone=user.phone,
            hashed_password=get_password_hash(user.password),
            role_id=3,
            device_id='test'
        )

        db.add(new_user)
        db.commit()
        logger.info(f"New user registered: {user.email}")
        return {"message": "User registered successfully", "email": user.email}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in signup: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post('/token')
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login user and return access token"""
    try:
        user = db.query(User).filter(User.email == form_data.username).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect email or password")
        
        access_token_expires = timedelta(minutes=30)
        token = create_access_token(
            data={"sub": user.email}, 
            expires_delta=access_token_expires
        )
        logger.info(f"User logged in: {user.email}")
        return {"access_token": token, "token_type": "bearer"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post('/forgot-password')
def forgot_password(email: str = Form(...), db: Session = Depends(get_db)):
    """Send password reset email"""
    try:
        # Check if user exists
        user = db.query(User).filter(User.email == email).first()
        if not user:
            # For security, don't reveal if email exists or not
            return {"message": "If the email exists in our system, a password reset link has been sent"}
        
        # Create reset token (expires in 30 minutes)
        reset_token_expires = timedelta(minutes=30)
        token = create_access_token(
            data={"sub": email, "purpose": "password_reset"}, 
            expires_delta=reset_token_expires
        )
        
        # Send reset email
        send_reset_email(email, token)
        logger.info(f"Password reset email sent to: {email}")
        
        return {"message": "Password reset email sent successfully", "status": "success"}
        
    except Exception as e:
        logger.error(f"Error in forgot_password for {email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send reset email. Please try again later.")

@app.post('/reset-password')
def reset_password(
    token: str = Form(...), 
    new_password: str = Form(...), 
    db: Session = Depends(get_db)
):
    """Reset user password using token"""
    try:
        # Verify token
        email = verify_token(token)
        if not email:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        
        # Find user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Validate new password
        if len(new_password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
        
        # Update password
        user.hashed_password = get_password_hash(new_password)
        db.commit()
        
        logger.info(f"Password reset successful for: {email}")
        return {"message": "Password updated successfully", "status": "success"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in reset_password: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to reset password")

@app.post('/logout')
def logout():
    """Logout user (client-side token removal)"""
    return {"message": "Logged out successfully", "status": "success"}

@app.get('/health')
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "API is running"}

# Test endpoint to verify user exists (for development only)
@app.get('/user/{email}')
def get_user_info(email: str, db: Session = Depends(get_db)):
    """Get user info by email (development only)"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "user_id": user.user_Id,
        "fname": user.fname,
        "email": user.email,
        "phone": user.phone,
        "role_id": user.role_id,
        "is_active": user.isActive,
        "added_on": user.added_on
    }
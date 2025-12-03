from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from app.auth.auth_models import UserCreate, Token, User
from app.auth.auth_service import (
    get_password_hash,
    verify_password,
    create_access_token
)
from app.database.mongodb import get_database
from app.config import settings
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db=Depends(get_database)):
    """Register a new user"""
    
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_dict = {
        "email": user.email,
        "hashed_password": hashed_password,
        "created_at": datetime.utcnow(),
        "scan_history": [],
        "is_active": True
    }
    
    result = await db.users.insert_one(user_dict)
    created_user = await db.users.find_one({"_id": result.inserted_id})
    
    return User(
        id=str(created_user["_id"]),
        email=created_user["email"],
        created_at=created_user["created_at"],
        is_active=created_user["is_active"],
        scan_count=len(created_user.get("scan_history", []))
    )


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db=Depends(get_database)
):
    """Login and get JWT token"""
    
    # Find user
    try:
        logger.info(f"Login attempt for email: {form_data.username}")
        user = await db.users.find_one({"email": form_data.username})
    except Exception as e:
        logger.exception("Database error during login")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]},
        expires_delta=access_token_expires
    )
    
    return Token(access_token=access_token, token_type="bearer")

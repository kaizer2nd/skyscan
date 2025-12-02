from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from bson import ObjectId


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")


class ScanHistoryItem(BaseModel):
    """Individual scan history item"""
    scan_id: str
    timestamp: datetime
    scan_type: str  # "network", "cloud", "full"
    summary: str
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    full_report_json: Dict[str, Any] = Field(default_factory=dict)
    status: str = "completed"  # "pending", "running", "completed", "failed"


class UserBase(BaseModel):
    """User base model"""
    email: EmailStr


class UserCreate(UserBase):
    """User creation model"""
    password: str


class UserInDB(UserBase):
    """User in database model"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    scan_history: List[ScanHistoryItem] = Field(default_factory=list)
    is_active: bool = True
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class User(UserBase):
    """User response model"""
    id: str
    created_at: datetime
    is_active: bool
    scan_count: int = 0
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    """JWT Token model"""
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Token payload data"""
    email: Optional[str] = None

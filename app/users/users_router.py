from fastapi import APIRouter, Depends, HTTPException, status
from app.auth.auth_service import get_current_user_email
from app.database.mongodb import get_database
from app.users.users_models import UserInfo, ScanSummary, ScanDetail
from typing import List
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/user", tags=["Users"])


@router.get("/info", response_model=UserInfo)
async def get_user_info(
    current_user_email: str = Depends(get_current_user_email),
    db=Depends(get_database)
):
    """Get current user information"""
    
    user = await db.users.find_one({"email": current_user_email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserInfo(
        email=user["email"],
        created_at=user["created_at"],
        total_scans=len(user.get("scan_history", [])),
        is_active=user.get("is_active", True)
    )


@router.get("/history", response_model=List[ScanSummary])
async def get_scan_history(
    current_user_email: str = Depends(get_current_user_email),
    db=Depends(get_database)
):
    """Get user's scan history"""
    
    user = await db.users.find_one({"email": current_user_email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    scan_history = user.get("scan_history", [])
    
    # Convert to response model
    summaries = [
        ScanSummary(
            scan_id=scan["scan_id"],
            timestamp=scan["timestamp"],
            scan_type=scan["scan_type"],
            summary=scan["summary"],
            severity_counts=scan.get("severity_counts", {}),
            status=scan.get("status", "completed")
        )
        for scan in scan_history
    ]
    
    # Sort by timestamp descending
    summaries.sort(key=lambda x: x.timestamp, reverse=True)
    
    return summaries


@router.get("/scan/{scan_id}", response_model=ScanDetail)
async def get_scan_detail(
    scan_id: str,
    current_user_email: str = Depends(get_current_user_email),
    db=Depends(get_database)
):
    """Get detailed scan result by ID"""
    
    user = await db.users.find_one({"email": current_user_email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Find scan in history
    scan_history = user.get("scan_history", [])
    scan = next((s for s in scan_history if s["scan_id"] == scan_id), None)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return ScanDetail(
        scan_id=scan["scan_id"],
        timestamp=scan["timestamp"],
        scan_type=scan["scan_type"],
        summary=scan["summary"],
        severity_counts=scan.get("severity_counts", {}),
        full_report_json=scan.get("full_report_json", {}),
        status=scan.get("status", "completed")
    )

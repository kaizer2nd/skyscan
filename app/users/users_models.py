from pydantic import BaseModel
from typing import List, Dict, Any
from datetime import datetime


class UserInfo(BaseModel):
    """User information response"""
    email: str
    created_at: datetime
    total_scans: int
    is_active: bool


class ScanSummary(BaseModel):
    """Scan summary for dashboard"""
    scan_id: str
    timestamp: datetime
    scan_type: str
    summary: str
    severity_counts: Dict[str, int]
    status: str


class ScanDetail(BaseModel):
    """Detailed scan result"""
    scan_id: str
    timestamp: datetime
    scan_type: str
    summary: str
    severity_counts: Dict[str, int]
    full_report_json: Dict[str, Any]
    status: str

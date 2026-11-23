from pydantic import BaseModel, ConfigDict
from datetime import datetime

class ScanResponse(BaseModel):
    id: int
    started_at: datetime
    completed_at: datetime | None  
    status: str
    region: str
    total_findings: int
    risk_score: float | None
    error_message: str | None

    model_config = ConfigDict(from_attributes=True)

class ScanRequest(BaseModel):
    region: str = "us-east-1"

    model_config = ConfigDict(from_attributes=True)


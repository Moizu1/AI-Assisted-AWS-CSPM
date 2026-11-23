from datetime import datetime
from pydantic import BaseModel, ConfigDict

class FindingResponse(BaseModel):
    id: int
    scan_id: int
    resource_type: str
    resource_name: str
    check: str
    severity: str
    recommendation: str | None
    exposure: int | None
    asset_sensitivity: int | None
    exploitability: int | None
    score: float | None
    risk_level: str | None
    issue_resolved: bool
    first_detected_at: datetime
    last_detected_at: datetime

    model_config = ConfigDict(from_attributes=True)
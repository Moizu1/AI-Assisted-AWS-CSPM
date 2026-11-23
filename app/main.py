from fastapi import FastAPI
from app.api.scans import router as scans_router
from app.api.dashboard import router as dashboard_router
from app.api.auth import router as auth_router
from app.api.users import router as users_router

app = FastAPI(title="AWS CSPM API")
app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])
app.include_router(
    dashboard_router,
    prefix="/api/dashboard",
    tags=["Dashboard"]
)

app.include_router(
    auth_router,
    prefix="/api/auth",
    tags=["Authentication"]
)

app.include_router(
    users_router,
    prefix="/api/users",
    tags=["User Management"]
)
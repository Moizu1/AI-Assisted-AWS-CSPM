from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional


class UserRegister(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    organization: Optional[str] = Field(default=None, max_length=150)
    contact_number: Optional[str] = Field(default=None, max_length=30)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    email: EmailStr
    organization: Optional[str]
    contact_number: Optional[str]
    role: str
    status: str
    is_two_factor_enabled: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
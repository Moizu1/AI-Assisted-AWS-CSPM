import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")

    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )

    def validate(self):
        if not self.JWT_SECRET_KEY:
            raise ValueError("JWT_SECRET_KEY is missing from .env")

        if len(self.JWT_SECRET_KEY) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters")

        if self.JWT_ALGORITHM != "HS256":
            raise ValueError("Unsupported JWT algorithm")


settings = Settings()
import os
from pydantic_settings import BaseSettings

from pydantic import ConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "HMACFR Backend"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-hmacfr-key-change-in-production")
    ENCRYPTION_SECRET_KEY: str = os.getenv("ENCRYPTION_SECRET_KEY", os.getenv("SECRET_KEY", "super-secret-hmacfr-key-change-in-production"))
    HASH_ALGORITHM: str = "SHA256"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    EVENT_BROKER_TYPE: str = os.getenv("EVENT_BROKER_TYPE", "memory")
    
    # CORS Settings
    CORS_ORIGINS: list = ["*"]

    # Paths

    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    UPLOADS_DIR: str = os.path.join(BASE_DIR, "uploads")
    EVIDENCE_VAULT_DIR: str = os.path.join(BASE_DIR, "evidence_vault")
    LOGS_DIR: str = os.path.join(BASE_DIR, "logs")
    
    # Database
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'hmacfr.db')}"

    model_config = ConfigDict(case_sensitive=True, extra="ignore")

settings = Settings()

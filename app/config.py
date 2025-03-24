from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Application settings."""
    
    # Database settings
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5434/docker_matcher"
    
    # API settings
    API_V1_STR: str = "/api/v1"
    
    # CORS settings
    CORS_ORIGINS: str = "*"  # Changed to str, we'll handle list conversion in property
    
    # Application settings
    PROJECT_NAME: str = "Docker Source Matcher"
    VERSION: str = "0.1.0"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Convert CORS_ORIGINS string to list."""
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

settings = Settings() 
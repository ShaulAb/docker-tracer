"""Application configuration using Pydantic settings."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class MatchingWeights(BaseModel):
    """Weights for different aspects of Dockerfile matching."""
    base_image: float = Field(0.3, description="Weight for base image matching")
    layer_match: float = Field(0.4, description="Weight for layer matching")
    metadata: float = Field(0.15, description="Weight for metadata matching")
    context: float = Field(0.15, description="Weight for build context matching")

    @field_validator('*')
    def validate_weights(cls, v: float) -> float:
        """Validate that weights are between 0 and 1."""
        if not 0 <= v <= 1:
            raise ValueError("Weight must be between 0 and 1")
        return v

class MatchingThresholds(BaseModel):
    """Thresholds for different match quality levels."""
    likely_match: float = Field(0.8, description="Threshold for likely matches")
    excellent_match: float = Field(0.9, description="Threshold for excellent matches")
    good_match: float = Field(0.8, description="Threshold for good matches")
    fair_match: float = Field(0.6, description="Threshold for fair matches")
    poor_match: float = Field(0.4, description="Threshold for poor matches")

    @field_validator('*')
    def validate_thresholds(cls, v: float) -> float:
        """Validate that thresholds are between 0 and 1."""
        if not 0 <= v <= 1:
            raise ValueError("Threshold must be between 0 and 1")
        return v

class LayerMatching(BaseModel):
    """Configuration for layer matching."""
    exact_match_threshold: float = Field(0.95, description="Threshold for exact matches")
    partial_match_threshold: float = Field(0.7, description="Threshold for partial matches")
    sequence_weight: float = Field(0.3, description="Weight for sequence matching")
    command_weight: float = Field(0.7, description="Weight for command matching")

class PathMatching(BaseModel):
    """Configuration for path pattern matching."""
    exact_path_score: float = Field(1.0, description="Score for exact path matches")
    parent_path_score: float = Field(0.8, description="Score for parent path matches")
    filename_only_score: float = Field(0.6, description="Score for filename matches")
    extension_match_score: float = Field(0.3, description="Score for extension matches")

class LabelMatching(BaseModel):
    """Configuration for label matching importance."""
    maintainer: float = Field(0.4, description="Weight for maintainer label")
    version: float = Field(0.3, description="Weight for version label")
    description: float = Field(0.2, description="Weight for description label")
    other: float = Field(0.1, description="Weight for other labels")

class ContextMatching(BaseModel):
    """Configuration for build context analysis."""
    file_presence_weight: float = Field(0.6, description="Weight for file presence")
    path_pattern_weight: float = Field(0.4, description="Weight for path patterns")

class CommandTypeWeights(BaseModel):
    """Weights for different Dockerfile command types."""
    RUN: float = Field(1.0, description="Weight for RUN commands")
    COPY: float = Field(0.8, description="Weight for COPY commands")
    ADD: float = Field(0.8, description="Weight for ADD commands")
    ENV: float = Field(0.6, description="Weight for ENV commands")
    WORKDIR: float = Field(0.4, description="Weight for WORKDIR commands")
    EXPOSE: float = Field(0.4, description="Weight for EXPOSE commands")
    VOLUME: float = Field(0.4, description="Weight for VOLUME commands")
    LABEL: float = Field(0.3, description="Weight for LABEL commands")
    USER: float = Field(0.3, description="Weight for USER commands")
    ARG: float = Field(0.2, description="Weight for ARG commands")
    OTHER: float = Field(0.1, description="Weight for other commands")

class MatchingSettings(BaseModel):
    """All settings related to Dockerfile matching."""
    score_weights: MatchingWeights = MatchingWeights()
    thresholds: MatchingThresholds = MatchingThresholds()
    layer_matching: LayerMatching = LayerMatching()
    path_matching: PathMatching = PathMatching()
    label_matching: LabelMatching = LabelMatching()
    context_matching: ContextMatching = ContextMatching()
    command_type_weights: CommandTypeWeights = CommandTypeWeights()

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

    # GitHub settings
    GITHUB_TOKEN: Optional[str] = None

    # Matching settings
    matching: MatchingSettings = MatchingSettings()
    
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
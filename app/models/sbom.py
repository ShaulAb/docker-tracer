from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Column, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID

from app.database import Base

class SBOM(BaseModel):
    """SBOM data model."""
    source_type: str = Field(..., description="Type of the source (e.g., 'github', 'gitlab')")
    source_id: str = Field(..., description="Identifier of the source")
    metadata: Dict = Field(default_factory=dict, description="Additional metadata about the SBOM")
    components: List[Dict] = Field(default_factory=list, description="List of components in the SBOM")

    def model_dump(self) -> Dict:
        """Override model_dump to ensure consistent field names."""
        data = super().model_dump()
        return {
            "source_type": data["source_type"],
            "source_id": data["source_id"],
            "components": data["components"],
            "metadata": data["metadata"]
        }

class SBOMRecord(Base):
    """Database model for storing SBOMs."""
    __tablename__ = "sboms"

    id: UUID = Column(PostgresUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    source_type: str = Column(String, nullable=False)
    source_id: str = Column(String, nullable=False)
    sbom_data: Dict = Column(JSON, nullable=False)
    sbom_metadata: Dict = Column(JSON, nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class SBOMResponse(BaseModel):
    """Response model for SBOM queries."""
    id: UUID
    source_type: str
    source_id: str
    component_count: int
    created_at: datetime
    metadata: Dict = Field(default_factory=dict) 
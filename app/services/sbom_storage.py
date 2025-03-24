from typing import List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sbom import SBOM, SBOMRecord, SBOMResponse

class SBOMStorageError(Exception):
    """Raised when SBOM storage operations fail."""
    pass

class SBOMStorage:
    """Service for storing and retrieving SBOMs."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def store_sbom(self, sbom: SBOM) -> UUID:
        """Store an SBOM in the database."""
        try:
            # Convert SBOM to database record
            record = SBOMRecord(
                source_type=sbom.source_type,
                source_id=sbom.source_id,
                sbom_data=sbom.model_dump(),
                sbom_metadata=sbom.metadata
            )

            self.session.add(record)
            await self.session.commit()
            await self.session.refresh(record)

            return record.id

        except Exception as e:
            await self.session.rollback()
            raise SBOMStorageError(f"Failed to store SBOM: {str(e)}")

    async def get_sbom(self, sbom_id: UUID) -> Optional[SBOM]:
        """Retrieve an SBOM by ID."""
        try:
            query = select(SBOMRecord).where(SBOMRecord.id == sbom_id)
            result = await self.session.execute(query)
            record = result.scalar_one_or_none()

            if record is None:
                return None

            # Convert database record back to SBOM
            return SBOM(**record.sbom_data)

        except Exception as e:
            raise SBOMStorageError(f"Failed to retrieve SBOM: {str(e)}")

    async def get_sboms_by_source(self, source_type: str, source_id: str) -> List[SBOMResponse]:
        """Retrieve SBOMs by source type and ID."""
        try:
            query = select(SBOMRecord).where(
                SBOMRecord.source_type == source_type,
                SBOMRecord.source_id == source_id
            )
            result = await self.session.execute(query)
            records = result.scalars().all()

            return [
                SBOMResponse(
                    id=record.id,
                    source_type=record.source_type,
                    source_id=record.source_id,
                    component_count=len(record.sbom_data.get("components", [])),
                    created_at=record.created_at,
                    metadata=record.sbom_metadata
                )
                for record in records
            ]

        except Exception as e:
            raise SBOMStorageError(f"Failed to retrieve SBOMs by source: {str(e)}")

    async def delete_sbom(self, sbom_id: UUID) -> bool:
        """Delete an SBOM by ID."""
        try:
            query = select(SBOMRecord).where(SBOMRecord.id == sbom_id)
            result = await self.session.execute(query)
            record = result.scalar_one_or_none()

            if record is None:
                return False

            await self.session.delete(record)
            await self.session.commit()
            return True

        except Exception as e:
            await self.session.rollback()
            raise SBOMStorageError(f"Failed to delete SBOM: {str(e)}") 
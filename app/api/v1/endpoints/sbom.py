"""SBOM analysis endpoints."""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database import get_db
from app.models.sbom import SBOM, SBOMResponse
from app.services.sbom_generator import SBOMGenerator, SBOMGenerationError
from app.services.sbom_storage import SBOMStorage, SBOMStorageError

router = APIRouter()

class ContainerRequest(BaseModel):
    """Request model for container analysis."""
    image_ref: str

class RepositoryRequest(BaseModel):
    """Request model for repository analysis."""
    repo_path: str

@router.post("/analyze/container", response_model=SBOMResponse)
async def analyze_container(
    image_ref: str,
    db: AsyncSession = Depends(get_db)
) -> SBOMResponse:
    """Generate and store SBOM for a container image."""
    try:
        # Generate SBOM
        generator = SBOMGenerator()
        sbom = await generator.generate_container_sbom(image_ref)
        
        # Store SBOM
        storage = SBOMStorage(db)
        sbom_id = await storage.store_sbom(sbom)
        
        # Retrieve stored SBOM for response
        stored_sboms = await storage.get_sboms_by_source("container", image_ref)
        if not stored_sboms:
            raise HTTPException(status_code=500, detail="Failed to retrieve stored SBOM")
        
        return stored_sboms[0]

    except SBOMGenerationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SBOMStorageError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.post("/sbom/analyze/container", response_model=SBOM)
def analyze_container_sync(request: ContainerRequest) -> SBOM:
    """Generate SBOM for a container image synchronously."""
    try:
        # Generate SBOM
        generator = SBOMGenerator()
        sbom = generator.generate_container_sbom_sync(request.image_ref)
        return sbom

    except SBOMGenerationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.post("/sbom/analyze/repository", response_model=SBOM)
def analyze_repository_sync(request: RepositoryRequest) -> SBOM:
    """Generate SBOM for a repository synchronously."""
    try:
        # Generate SBOM
        generator = SBOMGenerator()
        sbom = generator.generate_repository_sbom_sync(request.repo_path)
        return sbom

    except SBOMGenerationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.post("/analyze/repository", response_model=SBOMResponse)
async def analyze_repository(
    repo_path: str,
    db: AsyncSession = Depends(get_db)
) -> SBOMResponse:
    """Generate and store SBOM for a local repository."""
    try:
        # Generate SBOM
        generator = SBOMGenerator()
        analyzer = generator.repository_analyzer
        sbom = await analyzer.analyze_repository(repo_path)
        
        # Store SBOM
        storage = SBOMStorage(db)
        sbom_id = await storage.store_sbom(sbom)
        
        # Retrieve stored SBOM for response
        stored_sboms = await storage.get_sboms_by_source("repository", repo_path)
        if not stored_sboms:
            raise HTTPException(status_code=500, detail="Failed to retrieve stored SBOM")
        
        return stored_sboms[0]

    except SBOMGenerationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SBOMStorageError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/sbom/{sbom_id}", response_model=SBOM)
async def get_sbom(
    sbom_id: UUID,
    db: AsyncSession = Depends(get_db)
) -> SBOM:
    """Retrieve an SBOM by ID."""
    try:
        storage = SBOMStorage(db)
        sbom = await storage.get_sbom(sbom_id)
        
        if sbom is None:
            raise HTTPException(status_code=404, detail="SBOM not found")
        
        return sbom

    except SBOMStorageError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/sboms/container/{image_ref}", response_model=List[SBOMResponse])
async def get_container_sboms(
    image_ref: str,
    db: AsyncSession = Depends(get_db)
) -> List[SBOMResponse]:
    """Retrieve all SBOMs for a container image."""
    try:
        storage = SBOMStorage(db)
        return await storage.get_sboms_by_source("container", image_ref)

    except SBOMStorageError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/sboms/repository/{repo_path:path}", response_model=List[SBOMResponse])
async def get_repository_sboms(
    repo_path: str,
    db: AsyncSession = Depends(get_db)
) -> List[SBOMResponse]:
    """Retrieve all SBOMs for a repository."""
    try:
        storage = SBOMStorage(db)
        return await storage.get_sboms_by_source("repository", repo_path)

    except SBOMStorageError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.delete("/sbom/{sbom_id}", response_model=bool)
async def delete_sbom(
    sbom_id: UUID,
    db: AsyncSession = Depends(get_db)
) -> bool:
    """Delete an SBOM by ID."""
    try:
        storage = SBOMStorage(db)
        deleted = await storage.delete_sbom(sbom_id)
        
        if not deleted:
            raise HTTPException(status_code=404, detail="SBOM not found")
        
        return True

    except SBOMStorageError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}") 
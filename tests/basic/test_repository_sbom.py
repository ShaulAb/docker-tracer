"""Basic synchronous tests for repository SBOM generation."""

from pathlib import Path
from app.services.sbom_generator import SBOMGenerator
from app.models.sbom import SBOM

# Get the path to the test fixtures
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
PYTHON_REPO = str(FIXTURES_DIR / "repositories" / "python")

def validate_basic_sbom_structure(sbom: SBOM):
    """Validate the basic structure of a generated SBOM."""
    assert sbom.source_type is not None
    assert sbom.source_id is not None
    assert isinstance(sbom.components, list)
    assert len(sbom.components) > 0
    assert sbom.metadata is not None

def test_direct_repository_sbom_generation():
    """Test synchronous generation of SBOM from a repository."""
    generator = SBOMGenerator()
    
    # Generate SBOM directly
    sbom = generator.generate_repository_sbom_sync(PYTHON_REPO)
    
    # Convert to dict for easier validation
    sbom_dict = sbom.model_dump()
    
    # Validate basic structure
    validate_basic_sbom_structure(sbom)
    
    # Validate repository-specific fields
    assert sbom_dict["source_type"] == "repository"
    assert sbom_dict["source_id"] == PYTHON_REPO
    
    # Validate metadata
    assert "repo_path" in sbom_dict["metadata"]
    assert sbom_dict["metadata"]["repo_path"] == PYTHON_REPO
    assert "generator" in sbom_dict["metadata"]
    assert "analysis_errors" in sbom_dict["metadata"]
    
    # Validate Python components
    component_names = {comp["name"] for comp in sbom_dict["components"]}
    assert "fastapi" in component_names, "FastAPI should be present"
    assert "sqlalchemy" in component_names, "SQLAlchemy should be present"
    
    # Validate component structure
    fastapi_component = next(c for c in sbom_dict["components"] if c["name"] == "fastapi")
    assert "version" in fastapi_component
    assert "type" in fastapi_component
    assert fastapi_component["type"] == "pip"  # Python packages use pip package manager 
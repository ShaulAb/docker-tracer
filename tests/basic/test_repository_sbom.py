"""Basic tests for repository SBOM generation."""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.services.sbom_generator import SBOMGenerator

# Get the path to the test fixtures
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

def validate_basic_sbom_structure(sbom_data):
    """Validate minimum required SBOM fields."""
    assert sbom_data["source_type"] == "repository"
    assert "source_id" in sbom_data
    assert "components" in sbom_data
    assert isinstance(sbom_data["components"], list)
    
    # Verify at least one component has basic properties
    if sbom_data["components"]:
        component = sbom_data["components"][0]
        assert "name" in component
        assert "version" in component
        assert "type" in component

def test_direct_python_repository_sbom_generation():
    """Test direct SBOM generation from Python repository without API."""
    repo_path = str(FIXTURES_DIR / "repositories" / "python")
    
    # Create generator and generate SBOM
    generator = SBOMGenerator()
    sbom = generator.generate_repository_sbom_sync(repo_path)
    
    # Convert to dict for validation
    sbom_dict = sbom.model_dump()
    
    # Validate structure
    validate_basic_sbom_structure(sbom_dict)
    assert sbom_dict["source_id"] == repo_path
    
    # Verify Python-specific components
    component_names = {comp["name"] for comp in sbom_dict["components"]}
    assert "fastapi" in component_names
    assert "uvicorn" in component_names
    assert "pytest" in component_names

def test_repository_sbom_endpoint(client):
    """Test repository SBOM generation via API endpoint."""
    repo_path = str(FIXTURES_DIR / "repositories" / "python")
    
    # Call API endpoint
    response = client.post("/api/v1/sbom/analyze/repository", 
                         json={"repo_path": repo_path})
    
    # Check response
    assert response.status_code == 200
    sbom_data = response.json()
    
    # Validate structure
    validate_basic_sbom_structure(sbom_data)
    assert sbom_data["source_id"] == repo_path
    
    # Verify Python-specific components
    component_names = {comp["name"] for comp in sbom_data["components"]}
    assert "fastapi" in component_names
    assert "uvicorn" in component_names
    assert "pytest" in component_names 
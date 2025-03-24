"""Basic tests for container SBOM generation."""

import pytest
from fastapi.testclient import TestClient

from app.services.sbom_generator import SBOMGenerator

def validate_basic_sbom_structure(sbom_data):
    """Validate minimum required SBOM fields."""
    assert sbom_data["source_type"] == "container"
    assert "source_id" in sbom_data
    assert "components" in sbom_data
    assert isinstance(sbom_data["components"], list)
    
    # Verify at least one component has basic properties
    if sbom_data["components"]:
        component = sbom_data["components"][0]
        assert "name" in component
        assert "version" in component
        assert "type" in component

def test_direct_container_sbom_generation():
    """Test direct SBOM generation from container without API."""
    image_ref = "nginx:latest"
    
    # Create generator and generate SBOM
    generator = SBOMGenerator()
    sbom = generator.generate_container_sbom_sync(image_ref)
    
    # Convert to dict for validation
    sbom_dict = sbom.model_dump()
    
    # Validate structure
    validate_basic_sbom_structure(sbom_dict)
    assert sbom_dict["source_id"] == image_ref
    
    # Verify metadata
    assert "metadata" in sbom_dict
    assert "image_ref" in sbom_dict["metadata"]
    assert sbom_dict["metadata"]["image_ref"] == image_ref

def test_container_sbom_endpoint(client):
    """Test container SBOM generation via API endpoint."""
    image_ref = "nginx:latest"
    
    # Call API endpoint
    response = client.post("/api/v1/sbom/analyze/container", 
                         json={"image_ref": image_ref})
    
    # Check response
    assert response.status_code == 200
    sbom_data = response.json()
    
    # Validate structure
    validate_basic_sbom_structure(sbom_data)
    assert sbom_data["source_id"] == image_ref 
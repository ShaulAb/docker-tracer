"""Basic synchronous tests for container SBOM generation."""

from pathlib import Path
from app.services.sbom_generator import SBOMGenerator
from app.models.sbom import SBOM

# Test constants
PYTHON_IMAGE = "python:3.12-slim"

def validate_basic_sbom_structure(sbom: SBOM):
    """Validate the basic structure of a generated SBOM."""
    assert sbom.source_type is not None
    assert sbom.source_id is not None
    assert isinstance(sbom.components, list)
    assert len(sbom.components) > 0
    assert sbom.metadata is not None

def test_direct_container_sbom_generation():
    """Test synchronous generation of SBOM from a container image."""
    generator = SBOMGenerator()
    
    # Generate SBOM directly
    sbom = generator.generate_container_sbom_sync(PYTHON_IMAGE)
    
    # Convert to dict for easier validation
    sbom_dict = sbom.model_dump()
    
    # Validate basic structure
    validate_basic_sbom_structure(sbom)
    
    # Validate container-specific fields
    assert sbom_dict["source_type"] == "container"
    assert sbom_dict["source_id"] == PYTHON_IMAGE
    
    # Validate metadata
    assert "image_ref" in sbom_dict["metadata"]
    assert sbom_dict["metadata"]["image_ref"] == PYTHON_IMAGE
    assert "generator" in sbom_dict["metadata"]
    assert "generator_version" in sbom_dict["metadata"]
    
    # Validate Python components
    component_names = {comp["name"] for comp in sbom_dict["components"]}
    assert "python" in component_names, "Python runtime should be present"
    assert "pip" in component_names, "pip should be present"
    
    # Validate component structure
    python_component = next(c for c in sbom_dict["components"] if c["name"] == "python")
    assert "version" in python_component
    assert "type" in python_component
    assert python_component["type"] == "binary"

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
"""Basic synchronous tests combining container and repository SBOM generation."""

from pathlib import Path
from app.services.sbom_generator import SBOMGenerator
from app.models.sbom import SBOM
from typing import List, Dict

# Test constants
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
PYTHON_REPO = str(FIXTURES_DIR / "repositories" / "python")
PYTHON_IMAGE = "python:3.12-slim"

def validate_basic_sbom_structure(sbom: SBOM):
    """Validate the basic structure of a generated SBOM."""
    assert sbom.source_type is not None
    assert sbom.source_id is not None
    assert isinstance(sbom.components, list)
    assert len(sbom.components) > 0
    assert sbom.metadata is not None

def validate_python_components(components: List[Dict], is_container: bool):
    """Validate Python-specific components in the SBOM."""
    # Ensure we have components
    assert len(components) > 0, "No components found"
    
    if is_container:
        # Container should have Python runtime as binary
        python_components = [c for c in components if c["name"].lower() == "python"]
        assert len(python_components) > 0, "No Python runtime found in container"
        assert any(c["type"] == "binary" for c in python_components), "Python runtime should be binary type in container"
    else:
        # Repository should have Python packages from requirements.txt
        python_packages = [c for c in components if c["type"] == "pip"]
        assert len(python_packages) > 0, "No Python packages found in repository"
        # Verify some expected packages are present
        package_names = {p["name"].lower() for p in python_packages}
        expected_packages = {"fastapi", "uvicorn", "sqlalchemy"}
        found_packages = expected_packages & package_names
        assert found_packages, f"Expected to find some of {expected_packages} in {package_names}"

def test_combined_python_analysis():
    """Test analyzing both Python container and repository, then comparing results."""
    generator = SBOMGenerator()
    
    # Generate container SBOM
    container_sbom = generator.generate_container_sbom_sync(PYTHON_IMAGE)
    container_dict = container_sbom.model_dump()
    
    # Generate repository SBOM
    repo_sbom = generator.generate_repository_sbom_sync(PYTHON_REPO)
    repo_dict = repo_sbom.model_dump()
    
    # Validate basic structure
    validate_basic_sbom_structure(container_sbom)
    validate_basic_sbom_structure(repo_sbom)
    
    # Validate source types and IDs
    assert container_dict["source_type"] == "container"
    assert container_dict["source_id"] == PYTHON_IMAGE
    assert repo_dict["source_type"] == "repository"
    assert repo_dict["source_id"] == PYTHON_REPO
    
    # Validate metadata
    assert "image_ref" in container_dict["metadata"]
    assert container_dict["metadata"]["image_ref"] == PYTHON_IMAGE
    assert "repo_path" in repo_dict["metadata"]
    assert repo_dict["metadata"]["repo_path"] == PYTHON_REPO
    
    # Validate components
    validate_python_components(container_dict["components"], is_container=True)
    validate_python_components(repo_dict["components"], is_container=False)
    
    # Compare components between container and repository
    container_components = {
        (comp["name"], comp.get("version"), comp.get("type"))
        for comp in container_dict["components"]
    }
    repo_components = {
        (comp["name"], comp.get("version"), comp.get("type"))
        for comp in repo_dict["components"]
    }
    
    # Debug output
    print("\nContainer components:")
    for name, version, type_ in sorted(container_components):
        print(f"  {name} ({type_}): {version}")
    
    print("\nRepository components:")
    for name, version, type_ in sorted(repo_components):
        print(f"  {name} ({type_}): {version}")
    
    # Verify Python runtime presence in both
    assert any(name.lower() == "python" for name, _, _ in container_components), "Python missing from container"
    assert any(name.lower() == "python" for name, _, _ in repo_components), "Python missing from repository"
    
    # Verify component types are correct
    container_types = {type_ for _, _, type_ in container_components if type_}
    repo_types = {type_ for _, _, type_ in repo_components if type_}
    
    assert "binary" in container_types, "Container should have binary components"
    assert "pip" in repo_types, "Repository should have pip components" 
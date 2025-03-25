"""Tests for Docker service exceptions."""

import pytest
from app.services.dockersdk.exceptions import (
    DockerServiceError,
    ImageNotFoundError,
    InspectionError,
    LayerAnalysisError,
    ConfigurationError,
    PackageAnalysisError,
)

def test_docker_service_error():
    """Test base Docker service error."""
    error = DockerServiceError("test error")
    assert str(error) == "test error"
    assert isinstance(error, Exception)

def test_image_not_found_error():
    """Test image not found error."""
    error = ImageNotFoundError("test:latest")
    assert str(error) == "Image 'test:latest' not found"
    assert isinstance(error, DockerServiceError)

def test_inspection_error():
    """Test inspection error."""
    error = InspectionError("test:latest", "Failed to inspect")
    assert str(error) == "Failed to inspect image 'test:latest': Failed to inspect"
    assert isinstance(error, DockerServiceError)

def test_layer_analysis_error():
    """Test layer analysis error."""
    error = LayerAnalysisError("test:latest", "Failed to analyze layers")
    assert str(error) == "Failed to analyze layers for image 'test:latest': Failed to analyze layers"
    assert isinstance(error, DockerServiceError)

def test_configuration_error():
    """Test configuration error."""
    error = ConfigurationError("Invalid configuration")
    assert str(error) == "Docker configuration error: Invalid configuration"
    assert isinstance(error, DockerServiceError)

def test_package_analysis_error():
    """Test package analysis error."""
    error = PackageAnalysisError("test:latest", "Failed to analyze packages")
    assert str(error) == "Failed to analyze packages in image 'test:latest': Failed to analyze packages"
    assert isinstance(error, DockerServiceError)

def test_error_inheritance():
    """Test error class inheritance."""
    assert issubclass(ImageNotFoundError, DockerServiceError)
    assert issubclass(InspectionError, DockerServiceError)
    assert issubclass(LayerAnalysisError, DockerServiceError)
    assert issubclass(ConfigurationError, DockerServiceError)
    assert issubclass(PackageAnalysisError, DockerServiceError) 
"""Tests for Dockerfile analysis and matching."""

import pytest
from pathlib import Path
from app.services.sbom_generator.dockerfile_analyzer import DockerfileAnalyzer

# Sample Dockerfile content for testing
SIMPLE_DOCKERFILE = """
FROM python:3.12-slim
LABEL maintainer="test@example.com"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . /app
WORKDIR /app

CMD ["python", "app.py"]
"""

MULTISTAGE_DOCKERFILE = """
FROM node:16 AS builder
WORKDIR /build
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /build/dist /usr/share/nginx/html
"""

def test_simple_dockerfile_analysis():
    """Test analysis of a simple Dockerfile."""
    analyzer = DockerfileAnalyzer()
    result = analyzer.analyze_content(SIMPLE_DOCKERFILE)
    
    # Check base image
    assert result.base_image == "python:3.12-slim"
    
    # Check stages (should be empty for non-multistage)
    assert len(result.stages) == 0
    
    # Check package commands
    assert len(result.package_commands) == 2
    assert "apt-get install" in result.package_commands[0].content
    assert "pip install" in result.package_commands[1].content
    
    # Check copy commands
    assert len(result.copy_commands) == 2
    assert result.copy_commands[0].args == ["requirements.txt", "."]
    assert result.copy_commands[1].args == [".", "/app"]
    
    # Check metadata
    assert "maintainer" in result.metadata
    assert result.metadata["maintainer"] == "test@example.com"

def test_multistage_dockerfile_analysis():
    """Test analysis of a multi-stage Dockerfile."""
    analyzer = DockerfileAnalyzer()
    result = analyzer.analyze_content(MULTISTAGE_DOCKERFILE)
    
    # Check stages
    assert len(result.stages) == 1
    assert "builder" in result.stages
    
    # Check base image (should be first FROM)
    assert result.base_image == "node:16"
    
    # Check package commands
    assert len(result.package_commands) == 1
    assert "npm install" in result.package_commands[0].content
    
    # Check copy commands (including multi-stage copy)
    assert len(result.copy_commands) == 3  # package.json, ., and --from=builder
    assert result.copy_commands[0].args == ["package.json", "."]
    assert result.copy_commands[1].args == [".", "."]
    assert "--from=builder" in result.copy_commands[2].args

def test_invalid_dockerfile():
    """Test handling of invalid Dockerfile content."""
    analyzer = DockerfileAnalyzer()
    
    # Test empty content
    with pytest.raises(ValueError, match="No valid instructions found"):
        analyzer.analyze_content("")
    
    # Test missing FROM
    with pytest.raises(ValueError, match="No base image .* found"):
        analyzer.analyze_content("RUN echo test")

def test_package_detection():
    """Test detection of package installation commands."""
    analyzer = DockerfileAnalyzer()
    
    # Test various package managers
    test_commands = [
        "RUN apt-get install -y nginx",
        "RUN apk add --no-cache git",
        "RUN yum install -y python3",
        "RUN pip install requests",
        "RUN npm install express",
    ]
    
    for cmd in test_commands:
        result = analyzer.analyze_content(f"FROM alpine\n{cmd}")
        assert len(result.package_commands) == 1
        assert cmd in result.package_commands[0].content 
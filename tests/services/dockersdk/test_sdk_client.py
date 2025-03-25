"""Tests for SDK Docker client implementation."""

import pytest
import asyncio
from datetime import datetime
from app.services.dockersdk.sdk_client import SDKDockerClient
from app.services.dockersdk.models import ImageInfo, Layer, ImageConfig, CommandType, PackageManager
from app.services.dockersdk.exceptions import ImageNotFoundError, InspectionError, ConfigurationError
from .conftest import TEST_IMAGE, TEST_CONTAINER_NAME
import docker
from typing import AsyncIterator, Optional
from docker.errors import APIError

@pytest.mark.asyncio
async def test_inspect_image(sdk_docker_client: SDKDockerClient):
    """Test image inspection."""
    info = await sdk_docker_client.inspect_image(TEST_IMAGE)
    
    assert isinstance(info, ImageInfo)
    assert info.id
    assert TEST_IMAGE in info.tags
    assert isinstance(info.created, datetime)
    assert info.size > 0
    assert isinstance(info.layers, list)
    assert len(info.layers) > 0
    assert isinstance(info.config, ImageConfig)
    assert info.base_image

@pytest.mark.asyncio
async def test_get_image_history(sdk_docker_client: SDKDockerClient):
    """Test getting image history."""
    layers = await sdk_docker_client.get_image_history(TEST_IMAGE)
    
    assert isinstance(layers, list)
    assert len(layers) > 0
    
    layer = layers[0]
    assert isinstance(layer, Layer)
    assert layer.id
    assert isinstance(layer.created, datetime)
    assert layer.created_by
    assert isinstance(layer.size, int)
    assert isinstance(layer.command_type, CommandType)

@pytest.mark.asyncio
async def test_get_image_config(sdk_docker_client: SDKDockerClient):
    """Test getting image configuration."""
    config = await sdk_docker_client.get_image_config(TEST_IMAGE)
    
    assert isinstance(config, ImageConfig)
    assert isinstance(config.env, dict)
    assert isinstance(config.cmd, list)
    assert isinstance(config.entrypoint, list)
    assert isinstance(config.working_dir, str)
    assert isinstance(config.exposed_ports, set)
    assert isinstance(config.volumes, list)
    assert isinstance(config.labels, dict)

@pytest.mark.asyncio
async def test_analyze_layers(sdk_docker_client: SDKDockerClient):
    """Test layer analysis."""
    layers = await sdk_docker_client.analyze_layers(TEST_IMAGE)
    
    assert isinstance(layers, list)
    assert len(layers) > 0
    
    # Find a RUN layer with package commands
    package_layers = [l for l in layers if l.package_commands]
    assert len(package_layers) > 0
    
    pkg_cmd = package_layers[0].package_commands[0]
    assert pkg_cmd.manager in list(PackageManager)
    assert pkg_cmd.command
    assert isinstance(pkg_cmd.packages, list)

@pytest.mark.asyncio
async def test_get_package_commands(sdk_docker_client: SDKDockerClient):
    """Test extracting package commands."""
    commands = await sdk_docker_client.get_package_commands(TEST_IMAGE)
    
    assert isinstance(commands, list)
    assert len(commands) > 0
    
    cmd = commands[0]
    assert isinstance(cmd.manager, PackageManager)
    assert cmd.command
    assert isinstance(cmd.packages, list)
    assert isinstance(cmd.version_constraints, dict)

@pytest.mark.asyncio
async def test_nonexistent_image(sdk_docker_client: SDKDockerClient):
    """Test handling of nonexistent images."""
    with pytest.raises(ImageNotFoundError):
        await sdk_docker_client.inspect_image("nonexistent:latest")

# FUTURE: add tests for log streaming (runtime inspection)

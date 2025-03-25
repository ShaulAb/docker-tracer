"""Test fixtures for Docker service tests."""

import pytest
from docker import DockerClient
from docker.errors import ImageNotFound, NotFound, APIError
from typing import Generator, AsyncGenerator
from app.services.dockersdk.sdk_client import SDKDockerClient

# Test image to use for Docker operations
TEST_IMAGE = "python:3.9-slim"
TEST_CONTAINER_NAME = "docker-service-test"

@pytest.fixture
def docker_client() -> Generator[DockerClient, None, None]:
    """Provide a Docker SDK client."""
    client = DockerClient.from_env()
    yield client
    client.close()

@pytest.fixture
async def sdk_docker_client() -> AsyncGenerator[SDKDockerClient, None]:
    """Provide an SDK Docker client."""
    client = SDKDockerClient()
    yield client
    await client.close()

@pytest.fixture
async def test_container(docker_client: DockerClient) -> AsyncGenerator[str, None]:
    """
    Provide a test container.
    
    Pulls test image if not available and creates a container.
    Container is automatically stopped and removed after tests.
    """
    # Cleanup any existing container with the same name
    try:
        container = docker_client.containers.get(TEST_CONTAINER_NAME)
        container.stop()
        container.remove(force=True)
    except NotFound:
        pass

    # Pull image if not exists
    try:
        docker_client.images.get(TEST_IMAGE)
    except ImageNotFound:
        docker_client.images.pull(TEST_IMAGE)
    
    # Create and start container
    container = docker_client.containers.run(
        TEST_IMAGE,
        name=TEST_CONTAINER_NAME,
        command="tail -f /dev/null",  # Keep container running
        detach=True,
        remove=True
    )
    
    yield TEST_CONTAINER_NAME
    
    # Cleanup
    try:
        container = docker_client.containers.get(TEST_CONTAINER_NAME)
        container.stop()
        container.remove(force=True)
    except (NotFound, APIError):
        pass  # Container already removed 
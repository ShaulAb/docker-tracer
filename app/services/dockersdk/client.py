"""Abstract base class for Docker clients."""

from abc import ABC, abstractmethod
from typing import AsyncIterator, List

from .models import ImageConfig, ImageInfo, Layer, PackageCommand


class DockerClient(ABC):
    """Abstract base class defining the interface for Docker clients."""

    @abstractmethod
    async def inspect_image(self, image_name: str) -> ImageInfo:
        """Inspect a Docker image and return detailed information.
        
        Args:
            image_name: Name of the Docker image to inspect
            
        Returns:
            Detailed information about the image
            
        Raises:
            ImageNotFoundError: If the image does not exist
            InspectionError: If inspection fails
        """
        pass

    @abstractmethod
    async def get_image_history(self, image_name: str) -> List[Layer]:
        """Get the history of layers for a Docker image.
        
        Args:
            image_name: Name of the Docker image
            
        Returns:
            List of layers in the image
            
        Raises:
            ImageNotFoundError: If the image does not exist
            InspectionError: If history retrieval fails
        """
        pass

    @abstractmethod
    async def get_image_config(self, image_name: str) -> ImageConfig:
        """Get the configuration of a Docker image.
        
        Args:
            image_name: Name of the Docker image
            
        Returns:
            Image configuration details
            
        Raises:
            ImageNotFoundError: If the image does not exist
            InspectionError: If config retrieval fails
        """
        pass

    @abstractmethod
    async def analyze_layers(self, image_name: str) -> List[Layer]:
        """Analyze the layers of a Docker image.
        
        Args:
            image_name: Name of the Docker image
            
        Returns:
            List of analyzed layers with package information
            
        Raises:
            ImageNotFoundError: If the image does not exist
            LayerAnalysisError: If layer analysis fails
        """
        pass

    @abstractmethod
    async def get_package_commands(self, image_name: str) -> List[PackageCommand]:
        """Extract package management commands from a Docker image.
        
        Args:
            image_name: Name of the Docker image
            
        Returns:
            List of package commands found in the image
            
        Raises:
            ImageNotFoundError: If the image does not exist
            PackageAnalysisError: If package analysis fails
        """
        pass

    @abstractmethod
    async def stream_logs(self, container_id: str) -> AsyncIterator[str]:
        """Stream logs from a Docker container.
        
        Args:
            container_id: ID of the container
            
        Returns:
            Async iterator of log lines
            
        Raises:
            ConfigurationError: If log streaming fails
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the client and clean up any resources."""
        pass

    async def __aenter__(self):
        """Enter the async context."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the async context and ensure resources are cleaned up."""
        await self.close() 
"""Docker SDK client implementation."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, AsyncIterator
import re

import aiodocker
from aiodocker.exceptions import DockerError
import docker
from docker.errors import APIError

from .client import DockerClient
from .exceptions import (
    ConfigurationError,
    ImageNotFoundError,
    InspectionError,
    LayerAnalysisError,
    PackageAnalysisError,
)
from .models import CommandType, ImageConfig, ImageInfo, Layer, PackageCommand
from .utils import parse_command_type, parse_package_command, parse_version_constraint


class SDKDockerClient(DockerClient):
    """Docker client implementation using the Docker SDK."""

    def __init__(self) -> None:
        """Initialize the Docker SDK client."""
        try:
            self.client = aiodocker.Docker()
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize Docker client: {str(e)}")

    async def _get_image(self, image_name: str) -> Dict[str, Any]:
        """Get a Docker image by name.
        
        Args:
            image_name: Name of the Docker image
            
        Returns:
            Docker image inspection data
            
        Raises:
            ImageNotFoundError: If the image does not exist
            InspectionError: If image retrieval fails
        """
        try:
            # First try to get the image
            await self.client.images.get(image_name)
            # If successful, get the inspection data
            return await self.client.images.inspect(image_name)
        except DockerError as e:
            if e.status == 404:
                raise ImageNotFoundError(image_name)
            raise InspectionError(image_name, str(e))

    def _parse_config(self, config: Dict[str, Any]) -> ImageConfig:
        """Parse Docker image configuration.
        
        Args:
            config: Raw configuration dictionary from Docker SDK
            
        Returns:
            Parsed ImageConfig object
        """
        # Extract environment variables
        env = {}
        for env_str in config.get('Env', []) or []:
            if '=' in env_str:
                key, value = env_str.split('=', 1)
                env[key] = value

        # Parse command and entrypoint
        cmd = config.get('Cmd', [])
        if isinstance(cmd, list):
            cmd = [str(c) for c in cmd]
        entrypoint = config.get('Entrypoint', [])
        if isinstance(entrypoint, list):
            entrypoint = [str(e) for e in entrypoint]

        # Get exposed ports
        exposed_ports = set(config.get('ExposedPorts', {}) or {}.keys())

        # Get volumes
        volumes = list((config.get('Volumes') or {}).keys())

        return ImageConfig(
            env=env,
            cmd=cmd or [],
            entrypoint=entrypoint or [],
            working_dir=config.get('WorkingDir', ''),
            user=config.get('User', ''),
            exposed_ports=exposed_ports,
            volumes=volumes,
            labels=config.get('Labels', {}) or {}
        )

    async def inspect_image(self, image_name: str) -> ImageInfo:
        """Inspect a Docker image and return detailed information.
        
        Args:
            image_name: Name of the image to inspect
            
        Returns:
            ImageInfo object containing image details
            
        Raises:
            ImageNotFoundError: If the image does not exist
            InspectionError: If inspection fails
        """
        try:
            inspect_data = await self._get_image(image_name)
            layers = await self.analyze_layers(image_name)
            config = self._parse_config(inspect_data['Config'])
            
            # Try to find base image from history
            base_image = None
            if layers:
                # The last layer usually contains the base image info
                last_layer = layers[-1]
                if 'FROM' in last_layer.created_by:
                    base_image = last_layer.created_by.split('FROM', 1)[1].strip()
                elif last_layer.created_by.startswith('#'):
                    # Handle buildkit format
                    parts = last_layer.created_by.split()
                    if len(parts) > 2:
                        base_image = parts[2].strip("'")

            return ImageInfo(
                id=inspect_data['Id'],
                tags=inspect_data.get('RepoTags', []),
                created=datetime.fromisoformat(inspect_data['Created'].rstrip('Z')),
                size=inspect_data['Size'],
                layers=layers,
                config=config,
                base_image=base_image
            )
        except DockerError as e:
            if 'No such image' in str(e):
                raise ImageNotFoundError(image_name)
            raise InspectionError(image_name, str(e))

    def _parse_timestamp(self, timestamp: Union[str, int]) -> datetime:
        """Parse a Docker timestamp into a datetime object.
        
        Args:
            timestamp: Either a string timestamp or Unix timestamp
            
        Returns:
            Parsed datetime object
        """
        if isinstance(timestamp, int):
            return datetime.fromtimestamp(timestamp)
        return datetime.fromisoformat(timestamp.rstrip('Z'))

    async def get_image_history(self, image_name: str) -> List[Layer]:
        """Get the history of layers for a Docker image."""
        try:
            history = await self.client.images.history(image_name)
        except DockerError as e:
            raise InspectionError(image_name, f"Failed to get image history: {str(e)}")

        layers = []
        for item in history:
            command_type = parse_command_type(item['CreatedBy'])
            
            # Parse package commands if it's a RUN command
            package_commands = []
            if command_type == CommandType.RUN:
                parsed = parse_package_command(item['CreatedBy'])
                if parsed:
                    package_commands.append(parsed)

            layers.append(Layer(
                id=item['Id'],
                created=self._parse_timestamp(item['Created']),
                created_by=item['CreatedBy'],
                size=item['Size'],
                command_type=command_type,
                package_commands=package_commands
            ))

        return layers

    async def get_image_config(self, image_name: str) -> ImageConfig:
        """Get the configuration of a Docker image."""
        try:
            inspect_data = await self._get_image(image_name)
            return self._parse_config(inspect_data['Config'])
        except DockerError as e:
            raise InspectionError(image_name, f"Failed to get image config: {str(e)}")

    async def analyze_layers(self, image_name: str) -> List[Layer]:
        """Analyze the layers of a Docker image.
        
        Args:
            image_name: Name of the image to analyze
            
        Returns:
            List of Layer objects
            
        Raises:
            LayerAnalysisError: If layer analysis fails
        """
        try:
            history = await self.client.images.history(image_name)
        except DockerError as e:
            raise LayerAnalysisError(image_name, str(e))

        layers = []
        for item in history:
            # Extract command from CreatedBy
            created_by = item.get('CreatedBy', '')
            
            # Handle buildkit format
            if created_by.startswith('#(nop)'):
                created_by = created_by.split('#(nop)', 1)[1].strip()
            elif '/bin/sh -c #(nop)' in created_by:
                created_by = created_by.split('/bin/sh -c #(nop)', 1)[1].strip()
            elif '/bin/sh -c' in created_by:
                created_by = created_by.split('/bin/sh -c', 1)[1].strip()
            
            # Remove quotes if present
            if created_by.startswith('"') and created_by.endswith('"'):
                created_by = created_by[1:-1]
            if created_by.startswith("'") and created_by.endswith("'"):
                created_by = created_by[1:-1]

            command_type = parse_command_type(created_by)
            
            # Parse package commands if it's a RUN command
            package_commands = []
            if command_type == CommandType.RUN:
                # Split multiple commands and handle shell operators
                for cmd in re.split(r'\s*(?:&&|\|\||\||;)\s*', created_by):
                    cmd = cmd.strip()
                    if cmd:
                        parsed = parse_package_command(cmd)
                        if parsed:
                            package_commands.append(parsed)

            layers.append(Layer(
                id=item.get('Id', '<missing>'),
                created=self._parse_timestamp(item['Created']),
                created_by=created_by,
                size=item['Size'],
                command_type=command_type,
                package_commands=package_commands
            ))

        return layers

    async def get_package_commands(self, image_name: str) -> List[PackageCommand]:
        """Extract package management commands from a Docker image."""
        try:
            layers = await self.get_image_history(image_name)
            commands = []
            for layer in layers:
                commands.extend(layer.package_commands)
            return commands
        except DockerError as e:
            raise PackageAnalysisError(image_name, f"Failed to extract package commands: {str(e)}")

    async def stream_logs(self, container_id: str) -> AsyncIterator[str]:
        """Stream logs from a container.
        
        Args:
            container_id: ID of the container to stream logs from
            
        Yields:
            Log lines as they become available
            
        Raises:
            ConfigurationError: If log streaming fails
        """
        try:
            container = self.client.containers.get(container_id)
            
            # Get logs as a stream
            logs = container.logs(
                stdout=True,
                stderr=True,
                follow=True,
                tail=10,
                stream=True
            )
            
            # Process the stream line by line
            for log_line in logs:
                if isinstance(log_line, bytes):
                    log_line = log_line.decode('utf-8')
                yield log_line.strip()

        except APIError as e:
            raise ConfigurationError(f"Failed to stream logs: {str(e)}")

    async def close(self) -> None:
        """Close the client and clean up resources."""
        await self.client.close() 
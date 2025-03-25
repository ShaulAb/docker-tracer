"""Container SBOM analysis using Syft CLI and Docker API."""

import asyncio
import json
import logging
import shutil
from datetime import datetime, UTC
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
from dataclasses import dataclass
from enum import Enum
from loguru import logger
import subprocess

from app.models.sbom import SBOM
from .exceptions import AnalysisError, InvalidImageError, NormalizationError
from .types import Component
from app.config import syft
from app.services.dockersdk.sdk_client import SDKDockerClient
from app.services.sbom_generator.models import (
    ContainerAnalysis,
    PackageInfo,
    PackageManager
)

logger = logger.bind(name=__name__)

class CommandType(Enum):
    """Types of Dockerfile commands that create layers."""
    RUN = "run"
    COPY = "copy"
    ADD = "add"
    FROM = "from"
    OTHER = "other"

@dataclass
class LayerInfo:
    """Information about a container layer."""
    layer_id: str
    created_by: str
    created_at: datetime
    size: int
    command_type: CommandType
    package_commands: List[str]

@dataclass
class ImageAnalysis:
    """Complete analysis of a container image."""
    layers: List[LayerInfo]
    config: Dict[str, Any]
    base_image: str
    total_size: int
    created_at: datetime

class DockerImageInspector:
    """Analyzes Docker images using Docker API via MCP."""

    def __init__(self):
        """Initialize the Docker image inspector."""
        self.image_cache = {}  # Cache inspection results
        self.package_patterns = [
            'apt-get install',
            'apk add',
            'yum install',
            'dnf install',
            'pip install',
            'npm install',
            'gem install'
        ]

    async def inspect_image(self, image_ref: str) -> Dict:
        """Inspect a Docker image and extract metadata.
        
        Args:
            image_ref: The container image reference
            
        Returns:
            Dict: Image metadata including layers and history
            
        Raises:
            AnalysisError: If inspection fails
        """
        try:
            # Check cache first
            if image_ref in self.image_cache:
                logger.debug(f"Using cached inspection result for {image_ref}")
                return self.image_cache[image_ref]

            # First try to list containers to see if image exists locally
            containers = await self._list_containers(filters={"ancestor": image_ref})
            
            # Get container info if it exists
            for container in containers:
                if container.get("Image") == image_ref:
                    result = {
                        "id": container.get("Id"),
                        "created": container.get("Created"),
                        "image": container.get("Image"),
                        "labels": container.get("Labels", {}),
                        "command": container.get("Command"),
                        "env": container.get("Env", []),
                        "working_dir": container.get("WorkingDir"),
                        "entrypoint": container.get("Entrypoint"),
                    }
                    # Cache the result
                    self.image_cache[image_ref] = result
                    return result
            
            return {}

        except Exception as e:
            logger.error(f"Failed to inspect image {image_ref}: {str(e)}")
            raise AnalysisError(f"Image inspection failed: {str(e)}")

    async def get_image_history(self, image_ref: str) -> List[Dict[str, Any]]:
        """Get the history of all layers in an image.
        
        Args:
            image_ref: The container image reference
            
        Returns:
            List[Dict]: List of layer history entries
            
        Raises:
            AnalysisError: If history retrieval fails
        """
        try:
            # First ensure we have basic image info
            image_info = await self.inspect_image(image_ref)
            if not image_info:
                logger.warning(f"No image info found for {image_ref}")
                return []

            # Get container ID if available
            container_id = image_info.get("id")
            if not container_id:
                logger.warning(f"No container ID found for {image_ref}")
                return []

            # Use MCP to get container details including history
            try:
                from mcp_mcp_server_docker_list_containers import mcp_mcp_server_docker_list_containers
                
                result = await mcp_mcp_server_docker_list_containers(
                    all=True,
                    filters={"id": container_id}
                )
                
                containers = result.get("containers", [])
                if not containers:
                    return []
                    
                # Extract history from container info
                container = containers[0]
                return container.get("history", [])

            except ImportError:
                logger.warning("MCP Docker module not available, returning empty history")
                return []

        except Exception as e:
            logger.error(f"Failed to get image history for {image_ref}: {str(e)}")
            raise AnalysisError(f"Failed to get image history: {str(e)}")

    async def get_image_config(self, image_ref: str) -> Dict[str, Any]:
        """Get detailed configuration information for an image.
        
        Args:
            image_ref: The container image reference
            
        Returns:
            Dict: Image configuration details
            
        Raises:
            AnalysisError: If config retrieval fails
        """
        try:
            # First get basic image info
            image_info = await self.inspect_image(image_ref)
            if not image_info:
                return {}

            # Extract config information
            config = {
                "id": image_info.get("id"),
                "created": image_info.get("created"),
                "labels": image_info.get("labels", {}),
                "env": image_info.get("env", []),
                "cmd": image_info.get("command"),
                "working_dir": image_info.get("working_dir"),
                "entrypoint": image_info.get("entrypoint"),
            }

            return config

        except Exception as e:
            logger.error(f"Failed to get image config for {image_ref}: {str(e)}")
            raise AnalysisError(f"Failed to get image config: {str(e)}")

    def analyze_layer_commands(self, history: List[Dict[str, Any]]) -> List[LayerInfo]:
        """Analyze commands from layer history and categorize them.
        
        Args:
            history: List of layer history entries
            
        Returns:
            List[LayerInfo]: Analyzed layer information
        """
        layers = []
        
        for entry in history:
            # Extract basic layer info
            layer_id = entry.get("id", "")
            created_by = entry.get("created_by", "")
            created_str = entry.get("created", "")
            size = entry.get("size", 0)
            
            # Parse creation time
            try:
                created_at = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                created_at = datetime.now(UTC)
            
            # Clean up command by removing shell prefix
            clean_cmd = created_by
            if clean_cmd.startswith("/bin/sh -c "):
                clean_cmd = clean_cmd[len("/bin/sh -c "):].strip()
            
            # Determine command type
            cmd_type = CommandType.OTHER
            cmd_lower = clean_cmd.lower()
            
            if cmd_lower.startswith("run ") or cmd_lower.startswith("#(nop) run "):
                cmd_type = CommandType.RUN
            elif cmd_lower.startswith("copy ") or cmd_lower.startswith("#(nop) copy "):
                cmd_type = CommandType.COPY
            elif cmd_lower.startswith("add ") or cmd_lower.startswith("#(nop) add "):
                cmd_type = CommandType.ADD
            elif cmd_lower.startswith("from ") or cmd_lower.startswith("#(nop) from "):
                cmd_type = CommandType.FROM
            
            # Extract package commands if present
            package_commands = []
            if any(pattern in cmd_lower for pattern in self.package_patterns):
                package_commands.append(created_by)
            
            # Create LayerInfo object
            layer = LayerInfo(
                layer_id=layer_id,
                created_by=created_by,
                created_at=created_at,
                size=size,
                command_type=cmd_type,
                package_commands=package_commands
            )
            
            layers.append(layer)
        
        return layers

    async def analyze_image(self, image_ref: str) -> ImageAnalysis:
        """Perform complete analysis of an image including history and config.
        
        Args:
            image_ref: The container image reference
            
        Returns:
            ImageAnalysis: Complete analysis results
            
        Raises:
            AnalysisError: If analysis fails
        """
        try:
            # Get image history
            history = await self.get_image_history(image_ref)
            
            # Get image config
            config = await self.get_image_config(image_ref)
            
            # Analyze layers
            layers = self.analyze_layer_commands(history)
            
            # Calculate total size
            total_size = sum(layer.size for layer in layers)
            
            # Get base image from first FROM layer
            base_image = ""
            for layer in layers:
                if layer.command_type == CommandType.FROM:
                    base_image = layer.created_by.split()[1]
                    break
            
            # Get creation time from config or latest layer
            created_at = None
            if config.get("created"):
                try:
                    created_at = datetime.fromisoformat(
                        config["created"].replace('Z', '+00:00')
                    )
                except (ValueError, AttributeError):
                    pass
            
            if not created_at and layers:
                created_at = max(layer.created_at for layer in layers)
            else:
                created_at = datetime.now(UTC)
            
            return ImageAnalysis(
                layers=layers,
                config=config,
                base_image=base_image,
                total_size=total_size,
                created_at=created_at
            )

        except Exception as e:
            logger.error(f"Failed to analyze image {image_ref}: {str(e)}")
            raise AnalysisError(f"Image analysis failed: {str(e)}")

    async def _list_containers(self, filters: Optional[Dict] = None) -> List[Dict]:
        """List Docker containers with optional filters.
        
        Args:
            filters: Container filters
            
        Returns:
            List[Dict]: List of container information
        """
        try:
            try:
                from mcp_mcp_server_docker_list_containers import mcp_mcp_server_docker_list_containers
                
                # Convert filters to Docker API format if provided
                filter_args = {"filters": filters} if filters else {}
                
                # List containers including stopped ones
                result = await mcp_mcp_server_docker_list_containers(all=True, **filter_args)
                return result.get("containers", [])

            except ImportError:
                logger.warning("MCP Docker module not available, returning empty list")
                return []

        except Exception as e:
            logger.error(f"Failed to list containers: {str(e)}")
            return []

    def extract_package_commands(self, history: List[Dict]) -> List[str]:
        """Extract package installation commands from container history.
        
        Args:
            history: Container layer history
            
        Returns:
            List[str]: List of package installation commands
        """
        package_commands = []
        
        for layer in history:
            cmd = layer.get('CreatedBy', '')
            if any(pattern in cmd.lower() for pattern in self.package_patterns):
                package_commands.append(cmd)
        
        return package_commands

    def match_dockerfile_instructions(self, history: List[Dict], dockerfile_instructions: List[Dict]) -> float:
        """Calculate similarity score between container history and Dockerfile.
        
        Args:
            history: Container layer history
            dockerfile_instructions: Parsed Dockerfile instructions
            
        Returns:
            float: Similarity score between 0 and 1
        """
        # TODO: Implement sophisticated matching algorithm
        # For now, return 0 as placeholder
        return 0.0

class ContainerAnalyzer:
    """Analyzes container images to generate SBOMs using Syft CLI."""

    def __init__(self):
        """Initialize the container analyzer."""
        # Check if syft is installed
        if not shutil.which("syft"):
            raise RuntimeError(
                "Syft CLI not found. Please install it from: "
                "https://github.com/anchore/syft#installation"
            )
        self.docker_inspector = DockerImageInspector()

    async def analyze_image(self, image_ref: str) -> SBOM:
        """Analyze a container image and generate an SBOM.
        
        Args:
            image_ref: The container image reference (e.g., 'nginx:latest')
            
        Returns:
            SBOM: The generated SBOM with normalized components
            
        Raises:
            InvalidImageError: If the image reference is invalid
            AnalysisError: If the analysis fails
        """
        try:
            # Validate image reference
            if not self.validate_image(image_ref):
                raise InvalidImageError(f"Invalid image reference: {image_ref}")

            # Get Docker image metadata
            docker_info = await self.docker_inspector.inspect_image(image_ref)

            # Run Syft analysis
            raw_result = await self._run_syft_analysis(image_ref)
            
            # Convert to our SBOM format
            sbom = self._convert_to_sbom(raw_result, image_ref)

            # Add Docker metadata if available
            if docker_info:
                sbom.metadata.update({
                    "docker_id": docker_info.get("id"),
                    "docker_created": docker_info.get("created"),
                    "docker_labels": docker_info.get("labels", {})
                })

            return sbom

        except Exception as e:
            logger.error(f"Failed to analyze container image {image_ref}: {str(e)}")
            raise AnalysisError(f"Failed to analyze container image: {str(e)}")

    def validate_image(self, image_ref: str) -> bool:
        """Validate if an image reference is valid.
        
        Args:
            image_ref: The container image reference to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Basic validation of image reference format
            if ":" not in image_ref:
                return False
            
            name, tag = image_ref.split(":", 1)
            if not name or not tag:
                return False

            # Check for valid registry URL if present
            if "/" in name:
                registry = name.split("/")[0]
                if "." in registry or ":" in registry:
                    parsed = urlparse(f"https://{registry}")
                    if not parsed.netloc:
                        return False

            return True

        except Exception as e:
            logger.warning(f"Image validation failed for {image_ref}: {str(e)}")
            return False

    async def _run_syft_analysis(self, image_ref: str) -> Dict:
        """Run Syft analysis on a container image.
        
        Args:
            image_ref: The container image reference
            
        Returns:
            Dict: The raw Syft analysis result
            
        Raises:
            AnalysisError: If the Syft analysis fails
        """
        try:
            # Prepare Syft command
            cmd = [
                "syft",
                image_ref,
                "-o",
                "json",
                "--scope",
                "all-layers"
            ]
            
            # Run Syft command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise AnalysisError(
                    f"Syft analysis failed with code {process.returncode}: {stderr.decode()}"
                )

            # Parse JSON output
            return json.loads(stdout.decode())

        except Exception as e:
            raise AnalysisError(f"Syft analysis failed: {str(e)}")

    def _convert_to_sbom(self, syft_result: Dict, image_ref: str) -> SBOM:
        """Convert Syft result to our SBOM format.
        
        Args:
            syft_result: The raw Syft analysis result
            image_ref: The container image reference
            
        Returns:
            SBOM: Our normalized SBOM format
        """
        try:
            # Extract components from Syft output
            components = []
            for artifact in syft_result.get("artifacts", []):
                component_dict = self._normalize_component(artifact)
                if component_dict:
                    component = Component.from_dict(component_dict)
                    components.append(component)

            # Create SBOM
            return SBOM(
                source_type="container",
                source_id=image_ref,
                metadata={
                    "image_ref": image_ref,
                    "generator": "syft",
                    "generator_version": syft_result.get("descriptor", {}).get("version", "unknown"),
                    "analysis_time": datetime.now(UTC).isoformat(),
                    "schema_version": syft_result.get("schema", {}).get("version", "unknown"),
                },
                components=[comp.to_dict() for comp in components]
            )

        except Exception as e:
            raise NormalizationError(f"Failed to normalize SBOM: {str(e)}")

    def _normalize_component(self, artifact: Dict) -> Optional[Dict]:
        """Normalize a Syft artifact to our component format.
        
        Args:
            artifact: The Syft artifact to normalize
            
        Returns:
            Dict: The normalized component or None if invalid
        """
        try:
            # Skip if missing required fields
            if not artifact.get("name") or not artifact.get("version"):
                return None

            # Generate PURL if not provided
            purl = artifact.get("purl") or self._generate_purl(artifact)

            return {
                "name": artifact["name"],
                "version": artifact["version"],
                "type": artifact.get("type", "unknown"),
                "purl": purl,
                "licenses": artifact.get("licenses", []),
                "hashes": {
                    hash_obj["algorithm"]: hash_obj["value"]
                    for hash_obj in artifact.get("hashes", [])
                },
                "metadata": {
                    "locations": artifact.get("locations", []),
                    "foundBy": artifact.get("foundBy", "unknown"),
                    "language": artifact.get("language", "unknown"),
                }
            }

        except Exception as e:
            logger.warning(f"Failed to normalize component {artifact.get('name')}: {str(e)}")
            return None

    def _generate_purl(self, artifact: Dict) -> str:
        """Generate a Package URL (purl) for an artifact.
        
        Args:
            artifact: The artifact to generate a purl for
            
        Returns:
            str: The generated purl
        """
        # Basic purl generation
        pkg_type = artifact.get("type", "generic").lower()
        return f"pkg:{pkg_type}/{artifact['name']}@{artifact['version']}" 
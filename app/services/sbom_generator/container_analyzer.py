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
import docker
from docker.models.containers import Container
from docker.models.images import Image

from app.models.sbom import SBOM
from .exceptions import AnalysisError, InvalidImageError, NormalizationError
from .types import Component
# from app.services.dockersdk.sdk_client import SDKDockerClient
# from app.services.sbom_generator.models import (
#     PackageManager
# )

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
    """Analyzes Docker images using Docker SDK."""

    def __init__(self):
        """Initialize the Docker image inspector."""
        try:
            self.client = docker.from_env()
            logger.debug("Initialized Docker client")
        except docker.errors.DockerException as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            raise AnalysisError(f"Docker client initialization failed: {e}")

        self.image_cache: Dict[str, Dict] = {}  # Cache inspection results
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

            # Run in thread pool since Docker SDK is synchronous
            def _inspect():
                try:
                    # Try to get image
                    image = self.client.images.get(image_ref)
                    inspection = self.client.api.inspect_image(image.id)
                    
                    # Get history using Docker SDK
                    history = []
                    for item in self.client.api.history(image_ref):
                        history_item = {
                            "Id": item.get("Id", "<missing>"),
                            "Created": item.get("Created"),
                            "CreatedBy": item.get("CreatedBy", ""),
                            "Size": item.get("Size", 0),
                            "Comment": item.get("Comment", ""),
                            "Tags": item.get("Tags", [])
                        }
                        history.append(history_item)
                    
                    # Extract all relevant fields
                    config = inspection.get("Config", {})
                    result = {
                        "Id": image.id,
                        "Created": inspection["Created"],
                        "Architecture": inspection.get("Architecture"),
                        "Os": inspection.get("Os"),
                        "Config": {
                            "Env": config.get("Env", []),
                            "Cmd": config.get("Cmd"),
                            "Entrypoint": config.get("Entrypoint"),
                            "WorkingDir": config.get("WorkingDir", ""),
                            "Labels": config.get("Labels", {}),
                            "ExposedPorts": config.get("ExposedPorts", {}),
                            "Volumes": config.get("Volumes", {}),
                        },
                        "History": history,
                        "RootFS": inspection.get("RootFS", {}),
                    }
                    return result
                except docker.errors.ImageNotFound:
                    # Try to pull the image
                    logger.info(f"Image {image_ref} not found locally, attempting to pull")
                    image = self.client.images.pull(image_ref)
                    inspection = self.client.api.inspect_image(image.id)
                    
                    # Get history using Docker SDK
                    history = []
                    for item in self.client.api.history(image_ref):
                        history_item = {
                            "Id": item.get("Id", "<missing>"),
                            "Created": item.get("Created"),
                            "CreatedBy": item.get("CreatedBy", ""),
                            "Size": item.get("Size", 0),
                            "Comment": item.get("Comment", ""),
                            "Tags": item.get("Tags", [])
                        }
                        history.append(history_item)
                    
                    # Extract all relevant fields
                    config = inspection.get("Config", {})
                    result = {
                        "Id": image.id,
                        "Created": inspection["Created"],
                        "Architecture": inspection.get("Architecture"),
                        "Os": inspection.get("Os"),
                        "Config": {
                            "Env": config.get("Env", []),
                            "Cmd": config.get("Cmd"),
                            "Entrypoint": config.get("Entrypoint"),
                            "WorkingDir": config.get("WorkingDir", ""),
                            "Labels": config.get("Labels", {}),
                            "ExposedPorts": config.get("ExposedPorts", {}),
                            "Volumes": config.get("Volumes", {}),
                        },
                        "History": history,
                        "RootFS": inspection.get("RootFS", {}),
                    }
                    return result

            # Run inspection in thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _inspect)
            
            # Cache the result
            self.image_cache[image_ref] = result
            return result

        except docker.errors.DockerException as e:
            logger.error(f"Failed to inspect image {image_ref}: {e}")
            raise AnalysisError(f"Image inspection failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error inspecting image {image_ref}: {e}")
            raise AnalysisError(f"Image inspection failed: {e}")

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
            # Get image inspection which includes history
            inspection = await self.inspect_image(image_ref)
            return inspection.get("history", [])

        except Exception as e:
            logger.error(f"Failed to get image history for {image_ref}: {e}")
            raise AnalysisError(f"Failed to get image history: {e}")

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
            # Get image inspection which includes config
            inspection = await self.inspect_image(image_ref)
            return {
                "id": inspection.get("id"),
                "created": inspection.get("created"),
                "labels": inspection.get("labels", {}),
                "env": inspection.get("env", []),
                "cmd": inspection.get("command"),
                "working_dir": inspection.get("working_dir"),
                "entrypoint": inspection.get("entrypoint"),
            }

        except Exception as e:
            logger.error(f"Failed to get image config for {image_ref}: {e}")
            raise AnalysisError(f"Failed to get image config: {e}")

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
            # Run in thread pool since Docker SDK is synchronous
            def _list():
                containers = self.client.containers.list(all=True, filters=filters)
                return [
                    {
                        "Id": c.id,
                        "Image": c.image.tags[0] if c.image.tags else c.image.id,
                        "Created": c.attrs["Created"],
                        "Labels": c.labels,
                        "Command": c.attrs["Config"]["Cmd"] if "Config" in c.attrs else None,
                        "Env": c.attrs["Config"]["Env"] if "Config" in c.attrs else [],
                        "WorkingDir": c.attrs["Config"]["WorkingDir"] if "Config" in c.attrs else "",
                        "Entrypoint": c.attrs["Config"]["Entrypoint"] if "Config" in c.attrs else None,
                    }
                    for c in containers
                ]

            # Run in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _list)

        except docker.errors.DockerException as e:
            logger.error(f"Failed to list containers: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing containers: {e}")
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
        # Check if syft CLI is available
        if not shutil.which("syft"):
            raise EnvironmentError(
                "Syft CLI not found. Please install syft: "
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
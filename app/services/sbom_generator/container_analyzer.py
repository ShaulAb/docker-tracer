"""Container SBOM analysis using Syft CLI."""

import asyncio
import json
import logging
import shutil
from datetime import datetime, UTC
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.models.sbom import SBOM
from .exceptions import AnalysisError, InvalidImageError, NormalizationError
from .types import Component

logger = logging.getLogger(__name__)

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

            # Run Syft analysis
            raw_result = await self._run_syft_analysis(image_ref)
            
            # Convert to our SBOM format
            return self._convert_to_sbom(raw_result, image_ref)

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
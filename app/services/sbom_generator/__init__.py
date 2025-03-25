"""SBOM Generator package for analyzing software components.

This package provides functionality for generating Software Bill of Materials (SBOM)
from various sources like container images and repositories. It uses the Syft CLI
tool for SBOM generation and provides a normalized format for component data.
"""

import asyncio
import subprocess
import json
from typing import Optional
from datetime import datetime, UTC
from pathlib import Path
from loguru import logger

from app.models.sbom import SBOM
from .container_analyzer import ContainerAnalyzer
from .repository_analyzer import RepositoryAnalyzer
from .exceptions import (
    SBOMGenerationError,
    InvalidImageError,
    AnalysisError,
    NormalizationError,
)

from app.services.dockersdk.models import PackageManager
from app.services.sbom_generator.dockerfile_analyzer import (
    DockerfileAnalysis,
    DockerfileAnalyzer,
)
from app.services.sbom_generator.repository_analyzer import RepositoryAnalysisResult


logger = logger.bind(name=__name__)

class SBOMGenerator:
    """Service for generating SBOMs from various sources."""

    def __init__(self):
        """Initialize the SBOM generator service."""
        self.container_analyzer = ContainerAnalyzer()
        self.repository_analyzer = RepositoryAnalyzer()

    async def generate_container_sbom(self, image_ref: str) -> SBOM:
        """Generate an SBOM for a container image asynchronously.
        
        Args:
            image_ref: The container image reference (e.g., 'nginx:latest')
            
        Returns:
            SBOM: The generated SBOM with normalized components
            
        Raises:
            SBOMGenerationError: If SBOM generation fails
        """
        try:
            return await self.container_analyzer.analyze_image(image_ref)
        except (InvalidImageError, AnalysisError) as e:
            logger.error(f"Failed to generate SBOM for container {image_ref}: {str(e)}")
            raise SBOMGenerationError(str(e))
        except Exception as e:
            logger.error(f"Unexpected error generating SBOM for container {image_ref}: {str(e)}")
            raise SBOMGenerationError(f"Unexpected error: {str(e)}")

    def generate_container_sbom_sync(self, image_ref: str) -> SBOM:
        """Generate an SBOM for a container image synchronously.
        
        Args:
            image_ref: The container image reference (e.g., 'nginx:latest')
            
        Returns:
            SBOM: The generated SBOM with normalized components
            
        Raises:
            SBOMGenerationError: If SBOM generation fails
        """
        try:
            # Validate image reference first
            if not self.container_analyzer.validate_image(image_ref):
                raise InvalidImageError(f"Invalid image reference: {image_ref}")

            # Run Syft command synchronously
            cmd = [
                "syft",
                image_ref,
                "-o",
                "json",
                "--scope",
                "all-layers"
            ]
            
            # Run Syft command
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            if process.returncode != 0:
                raise AnalysisError(
                    f"Syft analysis failed with code {process.returncode}: {process.stderr}"
                )

            # Parse JSON output
            syft_result = json.loads(process.stdout)
            
            # Convert to our SBOM format
            return self.container_analyzer._convert_to_sbom(syft_result, image_ref)
            
        except (InvalidImageError, AnalysisError) as e:
            logger.error(f"Failed to generate SBOM for container {image_ref}: {str(e)}")
            raise SBOMGenerationError(str(e))
        except Exception as e:
            logger.error(f"Unexpected error generating SBOM for container {image_ref}: {str(e)}")
            raise SBOMGenerationError(f"Unexpected error: {str(e)}")

    async def generate_repository_sbom(self, repo_path: str) -> SBOM:
        """Generate an SBOM for a source code repository asynchronously.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            SBOM: The generated SBOM with normalized components
            
        Raises:
            SBOMGenerationError: If SBOM generation fails
        """
        try:
            return await self.repository_analyzer.analyze_repository(repo_path)
        except AnalysisError as e:
            logger.error(f"Failed to generate SBOM for repository {repo_path}: {str(e)}")
            raise SBOMGenerationError(str(e))
        except Exception as e:
            logger.error(f"Unexpected error generating SBOM for repository {repo_path}: {str(e)}")
            raise SBOMGenerationError(f"Unexpected error: {str(e)}")

    def generate_repository_sbom_sync(self, repo_path: str) -> SBOM:
        """Generate an SBOM for a source code repository synchronously.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            SBOM: The generated SBOM with normalized components
            
        Raises:
            SBOMGenerationError: If SBOM generation fails
        """
        try:
            # Create a new event loop for this synchronous operation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.repository_analyzer.analyze_repository(repo_path))
            finally:
                loop.close()
                asyncio.set_event_loop(None)
        except AnalysisError as e:
            logger.error(f"Failed to generate SBOM for repository {repo_path}: {str(e)}")
            raise SBOMGenerationError(str(e))
        except Exception as e:
            logger.error(f"Unexpected error generating SBOM for repository {repo_path}: {str(e)}")
            raise SBOMGenerationError(f"Unexpected error: {str(e)}")

__all__ = [
    "SBOMGenerator",
    "ContainerAnalyzer",
    "SBOMGenerationError",
    "InvalidImageError",
    "AnalysisError",
    "NormalizationError",
    'DockerfileAnalysis',
    'RepositoryAnalysisResult',
    'PackageManager',
    'DockerfileAnalyzer',
    'RepositoryAnalyzer'
] 
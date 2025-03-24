"""Repository analyzer for SBOM generation."""

import asyncio
import json
import logging
import os
from datetime import datetime, UTC
from pathlib import Path
from typing import List, Optional, Tuple
from uuid import uuid4

from lib4sbom.data.file import SBOMFile
from lib4sbom.sbom import SBOM as Lib4SBOM

from app.models.sbom import SBOM
from .exceptions import AnalysisError, NormalizationError
from .types import (
    PackageManagerType,
    RepositoryFile,
    PackageDependency,
    RepositoryAnalysisResult,
)

logger = logging.getLogger(__name__)

class RepositoryAnalyzer:
    """Analyzes repositories to generate SBOMs."""

    PACKAGE_FILES = {
        "requirements.txt": PackageManagerType.PIP,
        "setup.py": PackageManagerType.PIP,
        "pyproject.toml": PackageManagerType.PIP,
        "package.json": PackageManagerType.NPM,
        "pom.xml": PackageManagerType.MAVEN,
        "build.gradle": PackageManagerType.GRADLE,
        "Cargo.toml": PackageManagerType.CARGO,
        "go.mod": PackageManagerType.GO,
        "composer.json": PackageManagerType.COMPOSER,
        "Gemfile": PackageManagerType.GEMFILE,
    }

    async def analyze_repository(self, repo_path: str) -> SBOM:
        """Analyze a repository and generate an SBOM.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            SBOM: The generated SBOM
            
        Raises:
            AnalysisError: If analysis fails
        """
        try:
            # Find all package manager files
            package_files = await self.detect_package_files(repo_path)
            if not package_files:
                raise AnalysisError(f"No supported package files found in {repo_path}")

            # Create lib4sbom SBOM
            lib_sbom = Lib4SBOM()
            lib_sbom.set_type("cyclonedx")  # Use CycloneDX format
            lib_sbom.set_version("1.4")  # Use CycloneDX 1.4
            lib_sbom.set_uuid(f"urn:uuid:{uuid4()}")
            lib_sbom.set_bom_version("1")

            # Analyze each file
            all_dependencies = []
            errors = []
            
            for pkg_file in package_files:
                try:
                    result = await self.analyze_package_file(pkg_file)
                    all_dependencies.extend(result.dependencies)
                    
                    # Add file to lib4sbom SBOM
                    sbom_file = SBOMFile()
                    sbom_file.initialise()
                    sbom_file.set_name(Path(pkg_file.path).name)
                    sbom_file.set_id(f"SPDXRef-File-{len(all_dependencies)}")
                    lib_sbom.add_files({sbom_file.get_name(): sbom_file.get_file()})
                    
                except Exception as e:
                    errors.append(f"Error analyzing {pkg_file.path}: {str(e)}")

            # Create our SBOM format
            return self._create_sbom(
                repo_path=repo_path,
                dependencies=all_dependencies,
                analysis_errors=errors
            )

        except Exception as e:
            raise AnalysisError(f"Repository analysis failed: {str(e)}")

    async def detect_package_files(self, repo_path: str) -> List[RepositoryFile]:
        """Find package manager files in repository.
        
        Args:
            repo_path: Path to repository root
            
        Returns:
            List[RepositoryFile]: Detected package files
        """
        package_files = []
        
        for root, _, files in os.walk(repo_path):
            for file_name in files:
                if file_name in self.PACKAGE_FILES:
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                        package_files.append(
                            RepositoryFile(
                                path=file_path,
                                type=self.PACKAGE_FILES[file_name],
                                content=content
                            )
                        )
                    except Exception as e:
                        logger.warning(f"Failed to read {file_path}: {str(e)}")
                        continue

        return package_files

    async def analyze_package_file(self, pkg_file: RepositoryFile) -> RepositoryAnalysisResult:
        """Analyze a package manager file.
        
        Args:
            pkg_file: Package file to analyze
            
        Returns:
            RepositoryAnalysisResult: Analysis results
            
        Raises:
            AnalysisError: If analysis fails
        """
        try:
            dependencies = []
            
            if pkg_file.type == PackageManagerType.PIP:
                dependencies = await self._analyze_python_dependencies(pkg_file)
            elif pkg_file.type == PackageManagerType.NPM:
                dependencies = await self._analyze_npm_dependencies(pkg_file)
            # Add more package manager support here

            return RepositoryAnalysisResult(
                package_files=[pkg_file],
                dependencies=dependencies,
                errors=[],
                metadata={
                    "file_path": pkg_file.path,
                    "package_manager": pkg_file.type.name,
                }
            )

        except Exception as e:
            raise AnalysisError(f"Failed to analyze {pkg_file.path}: {str(e)}")

    async def _analyze_python_dependencies(self, pkg_file: RepositoryFile) -> List[PackageDependency]:
        """Analyze Python dependencies from requirements.txt or similar.
        
        Args:
            pkg_file: Python package file
            
        Returns:
            List[PackageDependency]: Extracted dependencies
        """
        dependencies = []
        
        # Simple requirements.txt parsing
        if Path(pkg_file.path).name == "requirements.txt":
            for line in pkg_file.content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Basic version extraction, can be enhanced
                    parts = line.split("==")
                    if len(parts) == 2:
                        name, version = parts
                        dependencies.append(
                            PackageDependency(
                                name=name.strip(),
                                version=version.strip(),
                                type="pip"
                            )
                        )

        return dependencies

    async def _analyze_npm_dependencies(self, pkg_file: RepositoryFile) -> List[PackageDependency]:
        """Analyze NPM dependencies from package.json.
        
        Args:
            pkg_file: NPM package file
            
        Returns:
            List[PackageDependency]: Extracted dependencies
        """
        dependencies = []
        
        try:
            data = json.loads(pkg_file.content)
            
            # Regular dependencies
            for name, version in data.get("dependencies", {}).items():
                dependencies.append(
                    PackageDependency(
                        name=name,
                        version=version.strip("^~="),  # Remove version prefixes
                        type="npm"
                    )
                )
            
            # Dev dependencies
            for name, version in data.get("devDependencies", {}).items():
                dependencies.append(
                    PackageDependency(
                        name=name,
                        version=version.strip("^~="),
                        type="npm",
                        is_dev=True
                    )
                )
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse package.json: {str(e)}")
            
        return dependencies

    def _create_sbom(
        self,
        repo_path: str,
        dependencies: List[PackageDependency],
        analysis_errors: List[str]
    ) -> SBOM:
        """Create SBOM from analysis results.
        
        Args:
            repo_path: Repository path
            dependencies: List of found dependencies
            analysis_errors: List of errors during analysis
            
        Returns:
            SBOM: Generated SBOM
        """
        try:
            # Convert dependencies to SBOM components
            components = []
            for dep in dependencies:
                components.append({
                    "name": dep.name,
                    "version": dep.version,
                    "type": dep.type,
                    "purl": f"pkg:{dep.type}/{dep.name}@{dep.version}",
                    "licenses": [],  # Could be enhanced with license detection
                    "hashes": {},    # Could be enhanced with package hashing
                    "metadata": {
                        "is_dev": dep.is_dev,
                        **dep.metadata
                    }
                })

            return SBOM(
                source_type="repository",
                source_id=repo_path,
                metadata={
                    "repo_path": repo_path,
                    "generator": "repository_analyzer",
                    "analysis_errors": analysis_errors,
                    "analysis_time": datetime.now(UTC).isoformat(),
                },
                components=components
            )

        except Exception as e:
            raise NormalizationError(f"Failed to create SBOM: {str(e)}") 
"""Types package for SBOM generation."""

from .component import Component
from .repository import (
    PackageManagerType,
    RepositoryFile,
    PackageDependency,
    RepositoryAnalysisResult,
) 
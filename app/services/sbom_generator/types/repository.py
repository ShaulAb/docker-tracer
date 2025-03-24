"""Types for repository analysis."""

from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional

class PackageManagerType(Enum):
    """Supported package manager types."""
    PIP = auto()          # Python packages (requirements.txt, setup.py, pyproject.toml)
    NPM = auto()          # Node.js packages (package.json)
    MAVEN = auto()        # Java packages (pom.xml)
    GRADLE = auto()       # Java packages (build.gradle)
    CARGO = auto()        # Rust packages (Cargo.toml)
    GO = auto()           # Go packages (go.mod)
    COMPOSER = auto()     # PHP packages (composer.json)
    GEMFILE = auto()      # Ruby packages (Gemfile)

    @classmethod
    def from_file(cls, file_path: str) -> Optional["PackageManagerType"]:
        """Determine package manager type from file path.
        
        Args:
            file_path: Path to the package manager file
            
        Returns:
            PackageManagerType if recognized, None otherwise
        """
        file_name = Path(file_path).name.lower()
        
        if file_name in ["requirements.txt", "setup.py", "pyproject.toml"]:
            return cls.PIP
        elif file_name == "package.json":
            return cls.NPM
        elif file_name == "pom.xml":
            return cls.MAVEN
        elif file_name == "build.gradle":
            return cls.GRADLE
        elif file_name == "cargo.toml":
            return cls.CARGO
        elif file_name == "go.mod":
            return cls.GO
        elif file_name == "composer.json":
            return cls.COMPOSER
        elif file_name == "gemfile":
            return cls.GEMFILE
        return None

@dataclass
class RepositoryFile:
    """Represents a detected package manager file."""
    path: str
    type: PackageManagerType
    content: str

@dataclass
class PackageDependency:
    """Represents a single package dependency."""
    name: str
    version: str
    type: str  # Package type (e.g., 'npm', 'pip')
    is_dev: bool = False
    metadata: Dict = None

    def __post_init__(self):
        """Initialize default values."""
        if self.metadata is None:
            self.metadata = {}

@dataclass
class RepositoryAnalysisResult:
    """Result of repository analysis."""
    package_files: List[RepositoryFile]
    dependencies: List[PackageDependency]
    errors: List[str]
    metadata: Dict

    def __post_init__(self):
        """Initialize default values."""
        if self.errors is None:
            self.errors = []
        if self.metadata is None:
            self.metadata = {} 
"""Data models for Docker service operations."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Set


class CommandType(Enum):
    """Types of Docker commands found in image layers."""
    
    WORKDIR = "WORKDIR"
    ENV = "ENV"
    LABEL = "LABEL"
    EXPOSE = "EXPOSE"
    USER = "USER"
    RUN = "RUN"
    CMD = "CMD"
    ENTRYPOINT = "ENTRYPOINT"
    VOLUME = "VOLUME"
    COPY = "COPY"
    ADD = "ADD"
    ARG = "ARG"
    STOPSIGNAL = "STOPSIGNAL"
    SHELL = "SHELL"
    UNKNOWN = "UNKNOWN"


class PackageManager(Enum):
    """Supported package managers for dependency analysis."""
    
    APT = "apt"
    APT_GET = "apt-get"
    PIP = "pip"
    PIP3 = "pip3"
    NPM = "npm"
    YARN = "yarn"
    DNF = "dnf"
    YUM = "yum"
    APK = "apk"


@dataclass
class PackageCommand:
    """Represents a package management command found in a Docker layer."""
    
    manager: PackageManager
    command: str
    packages: List[str]
    version_constraints: Dict[str, str]


@dataclass
class Layer:
    """Represents a layer in a Docker image."""
    
    id: str
    created: datetime
    created_by: str
    size: int
    command_type: CommandType
    package_commands: List[PackageCommand]


@dataclass
class ImageConfig:
    """Configuration details of a Docker image."""
    
    env: Dict[str, str]
    cmd: List[str]
    entrypoint: List[str]
    working_dir: str
    exposed_ports: Set[str]
    volumes: List[str]
    labels: Dict[str, str]
    user: str = ""  # Default to empty string


@dataclass
class ImageInfo:
    """Complete information about a Docker image."""
    
    id: str
    tags: List[str]
    created: datetime
    size: int
    layers: List[Layer]
    config: ImageConfig
    base_image: Optional[str]


@dataclass
class LayerMatch:
    """Represents a match between a Dockerfile instruction and an image layer."""
    
    dockerfile_instruction: 'DockerInstruction'  # Forward reference
    layer_info: Layer
    match_score: float
    match_type: str  # 'exact', 'partial', 'none'
    details: Dict[str, any]  # Additional match details


@dataclass
class DockerfileMatch:
    """Results of matching a Dockerfile against a Docker image."""
    
    overall_score: float
    base_image_score: float
    layer_score: float
    metadata_score: float
    context_score: float
    matched_layers: List[LayerMatch]
    metadata: Dict[str, any]  # Additional matching metadata

    @property
    def is_likely_match(self) -> bool:
        """Check if the Dockerfile likely produced this image."""
        return self.overall_score >= 0.8  # 80% confidence threshold

    @property
    def match_quality(self) -> str:
        """Get a qualitative description of the match quality."""
        if self.overall_score >= 0.9:
            return "Excellent"
        elif self.overall_score >= 0.8:
            return "Good"
        elif self.overall_score >= 0.6:
            return "Fair"
        elif self.overall_score >= 0.4:
            return "Poor"
        else:
            return "Very Poor"

    def get_mismatch_reasons(self) -> List[str]:
        """Get list of reasons for mismatches."""
        reasons = []
        if self.base_image_score < 0.8:
            reasons.append("Base image mismatch")
        if self.layer_score < 0.7:
            reasons.append("Layer command mismatches")
        if self.metadata_score < 0.7:
            reasons.append("Metadata differences")
        if self.context_score < 0.7:
            reasons.append("Build context differences")
        return reasons 
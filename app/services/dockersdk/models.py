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
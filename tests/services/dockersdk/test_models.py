"""Tests for Docker service data models."""

import pytest
from datetime import datetime
from app.services.dockersdk.models import (
    CommandType,
    PackageManager,
    PackageCommand,
    Layer,
    ImageConfig,
    ImageInfo,
)

def test_command_type_enum():
    """Test CommandType enumeration."""
    assert CommandType.RUN.value == "RUN"
    assert CommandType.CMD.value == "CMD"
    assert CommandType.ENTRYPOINT.value == "ENTRYPOINT"
    assert CommandType.WORKDIR.value == "WORKDIR"
    assert CommandType.ENV.value == "ENV"
    assert CommandType.EXPOSE.value == "EXPOSE"
    assert CommandType.VOLUME.value == "VOLUME"
    assert CommandType.USER.value == "USER"
    assert CommandType.LABEL.value == "LABEL"
    assert CommandType.ADD.value == "ADD"
    assert CommandType.COPY.value == "COPY"
    assert CommandType.UNKNOWN.value == "UNKNOWN"

def test_package_manager_enum():
    """Test PackageManager enumeration."""
    assert PackageManager.APT.value == "apt"
    assert PackageManager.APT_GET.value == "apt-get"
    assert PackageManager.PIP.value == "pip"
    assert PackageManager.NPM.value == "npm"
    assert PackageManager.YARN.value == "yarn"
    assert PackageManager.DNF.value == "dnf"
    assert PackageManager.YUM.value == "yum"
    assert PackageManager.APK.value == "apk"

def test_package_command():
    """Test PackageCommand data class."""
    cmd = PackageCommand(
        manager=PackageManager.APT,
        command="install",
        packages=["python3", "nginx"],
        version_constraints={"python3": "3.9.5"}
    )
    
    assert cmd.manager == PackageManager.APT
    assert cmd.command == "install"
    assert cmd.packages == ["python3", "nginx"]
    assert cmd.version_constraints == {"python3": "3.9.5"}
    
    # Test equality
    cmd2 = PackageCommand(
        manager=PackageManager.APT,
        command="install",
        packages=["python3", "nginx"],
        version_constraints={"python3": "3.9.5"}
    )
    assert cmd == cmd2
    
    # Test inequality
    cmd3 = PackageCommand(
        manager=PackageManager.PIP,
        command="install",
        packages=["requests"],
        version_constraints={}
    )
    assert cmd != cmd3

def test_layer():
    """Test Layer data class."""
    now = datetime.now()
    layer = Layer(
        id="sha256:abc123",
        created=now,
        created_by="/bin/sh -c apt-get install python3",
        size=1024,
        command_type=CommandType.RUN,
        package_commands=[
            PackageCommand(
                manager=PackageManager.APT,
                command="install",
                packages=["python3"],
                version_constraints={}
            )
        ]
    )
    
    assert layer.id == "sha256:abc123"
    assert layer.created == now
    assert layer.created_by == "/bin/sh -c apt-get install python3"
    assert layer.size == 1024
    assert layer.command_type == CommandType.RUN
    assert len(layer.package_commands) == 1
    assert layer.package_commands[0].manager == PackageManager.APT
    
    # Test equality
    layer2 = Layer(
        id="sha256:abc123",
        created=now,
        created_by="/bin/sh -c apt-get install python3",
        size=1024,
        command_type=CommandType.RUN,
        package_commands=[
            PackageCommand(
                manager=PackageManager.APT,
                command="install",
                packages=["python3"],
                version_constraints={}
            )
        ]
    )
    assert layer == layer2

def test_image_config():
    """Test ImageConfig data class."""
    config = ImageConfig(
        env={"PATH": "/usr/local/bin"},
        cmd=["python", "app.py"],
        entrypoint=["/docker-entrypoint.sh"],
        working_dir="/app",
        exposed_ports={"8080/tcp"},
        volumes=["/data"],
        labels={"version": "1.0"}
    )
    
    assert config.env == {"PATH": "/usr/local/bin"}
    assert config.cmd == ["python", "app.py"]
    assert config.entrypoint == ["/docker-entrypoint.sh"]
    assert config.working_dir == "/app"
    assert config.exposed_ports == {"8080/tcp"}
    assert config.volumes == ["/data"]
    assert config.labels == {"version": "1.0"}
    
    # Test equality
    config2 = ImageConfig(
        env={"PATH": "/usr/local/bin"},
        cmd=["python", "app.py"],
        entrypoint=["/docker-entrypoint.sh"],
        working_dir="/app",
        exposed_ports={"8080/tcp"},
        volumes=["/data"],
        labels={"version": "1.0"}
    )
    assert config == config2

def test_image_info():
    """Test ImageInfo data class."""
    now = datetime.now()
    config = ImageConfig(
        env={},
        cmd=["python"],
        entrypoint=[],
        working_dir="/",
        exposed_ports=set(),
        volumes=[],
        labels={}
    )
    layer = Layer(
        id="sha256:def456",
        created=now,
        created_by="/bin/sh -c apt-get install python3",
        size=1024,
        command_type=CommandType.RUN,
        package_commands=[]
    )
    
    info = ImageInfo(
        id="sha256:abc123",
        tags=["python:3.9"],
        created=now,
        size=1024,
        config=config,
        layers=[layer],
        base_image="debian:buster"
    )
    
    assert info.id == "sha256:abc123"
    assert info.tags == ["python:3.9"]
    assert info.created == now
    assert info.size == 1024
    assert info.config == config
    assert info.layers == [layer]
    assert info.base_image == "debian:buster"
    
    # Test equality
    info2 = ImageInfo(
        id="sha256:abc123",
        tags=["python:3.9"],
        created=now,
        size=1024,
        config=config,
        layers=[layer],
        base_image="debian:buster"
    )
    assert info == info2 
"""Tests for Docker service utility functions."""

import pytest
from app.services.dockersdk.utils import (
    parse_command_type,
    parse_package_command,
    parse_version_constraint,
    parse_image_name,
    format_size,
)
from app.services.dockersdk.models import CommandType, PackageManager

def test_parse_command_type():
    """Test command type parsing."""
    assert parse_command_type("/bin/sh -c #(nop) CMD [\"python\"]") == CommandType.CMD
    assert parse_command_type("/bin/sh -c #(nop) ENTRYPOINT [\"/docker-entrypoint.sh\"]") == CommandType.ENTRYPOINT
    assert parse_command_type("/bin/sh -c apt-get update && apt-get install -y python") == CommandType.RUN
    assert parse_command_type("/bin/sh -c #(nop) WORKDIR /app") == CommandType.WORKDIR
    assert parse_command_type("/bin/sh -c #(nop) ENV PATH=/usr/local/bin") == CommandType.ENV
    assert parse_command_type("/bin/sh -c #(nop) EXPOSE 8080") == CommandType.EXPOSE
    assert parse_command_type("/bin/sh -c #(nop) VOLUME [/data]") == CommandType.VOLUME
    assert parse_command_type("/bin/sh -c #(nop) USER app") == CommandType.USER
    assert parse_command_type("/bin/sh -c #(nop) LABEL version=1.0") == CommandType.LABEL
    assert parse_command_type("/bin/sh -c #(nop) ADD file:abc123 /") == CommandType.ADD
    assert parse_command_type("/bin/sh -c #(nop) COPY file:abc123 /") == CommandType.COPY
    assert parse_command_type("unknown command") == CommandType.UNKNOWN

def test_parse_package_command():
    """Test package command parsing."""
    # APT commands
    cmd = parse_package_command("apt-get install -y python3=3.9.5-2 nginx")
    assert cmd.manager == PackageManager.APT_GET
    assert cmd.command == "install"
    assert cmd.packages == ["python3", "nginx"]
    assert cmd.version_constraints == {"python3": "3.9.5-2"}
    
    cmd = parse_package_command("apt install -y python3=3.9.5-2 nginx")
    assert cmd.manager == PackageManager.APT
    assert cmd.command == "install"
    assert cmd.packages == ["python3", "nginx"]
    assert cmd.version_constraints == {"python3": "3.9.5-2"}
    
    # PIP commands
    cmd = parse_package_command("pip install requests==2.26.0 flask>=2.0.0")
    assert cmd.manager == PackageManager.PIP
    assert cmd.command == "install"
    assert cmd.packages == ["requests", "flask"]
    assert cmd.version_constraints == {"requests": "2.26.0", "flask": ">=2.0.0"}
    
    # DNF/YUM commands
    cmd = parse_package_command("dnf install -y python3-3.9.5 nginx")
    assert cmd.manager == PackageManager.DNF
    assert cmd.command == "install"
    assert cmd.packages == ["python3", "nginx"]
    assert cmd.version_constraints == {"python3": "3.9.5"}
    
    # APK commands
    cmd = parse_package_command("apk add --no-cache python3=3.9.5-r0")
    assert cmd.manager == PackageManager.APK
    assert cmd.command == "add"
    assert cmd.packages == ["python3"]
    assert cmd.version_constraints == {"python3": "3.9.5-r0"}
    
    # NPM commands
    cmd = parse_package_command("npm install express@4.17.1 react@17.0.2")
    assert cmd.manager == PackageManager.NPM
    assert cmd.command == "install"
    assert cmd.packages == ["express", "react"]
    assert cmd.version_constraints == {"express": "4.17.1", "react": "17.0.2"}
    
    # YARN commands
    cmd = parse_package_command("yarn add lodash@4.17.21")
    assert cmd.manager == PackageManager.YARN
    assert cmd.command == "add"
    assert cmd.packages == ["lodash"]
    assert cmd.version_constraints == {"lodash": "4.17.21"}
    
    # Non-package commands
    assert parse_package_command("echo hello") is None
    assert parse_package_command("cd /app") is None

def test_parse_version_constraint():
    """Test version constraint parsing."""
    # APT style
    name, version = parse_version_constraint("package=1.2.3-1")
    assert name == "package"
    assert version == "1.2.3-1"

    # PIP style
    name, version = parse_version_constraint("requests>=2.25.1")
    assert name == "requests"
    assert version == ">=2.25.1"

    # No constraint
    name, version = parse_version_constraint("simple-package")
    assert name == "simple-package"
    assert version == ""

def test_parse_image_name():
    """Test image name parsing."""
    # Full image name with registry, repository and tag
    assert parse_image_name("registry.example.com/org/repo:tag") == {
        "registry": "registry.example.com",
        "repository": "org/repo",
        "tag": "tag"
    }
    
    # Image name with repository and tag
    assert parse_image_name("ubuntu:20.04") == {
        "registry": None,
        "repository": "ubuntu",
        "tag": "20.04"
    }
    
    # Image name with repository only (defaults to latest tag)
    assert parse_image_name("ubuntu") == {
        "registry": None,
        "repository": "ubuntu",
        "tag": "latest"
    }
    
    # Image name with digest
    assert parse_image_name("ubuntu@sha256:abc123") == {
        "registry": None,
        "repository": "ubuntu",
        "tag": "sha256:abc123"
    }

def test_format_size():
    """Test size formatting."""
    assert format_size(0) == "0 B"
    assert format_size(1024) == "1.0 KiB"
    assert format_size(1024 * 1024) == "1.0 MiB"
    assert format_size(1024 * 1024 * 1024) == "1.0 GiB"
    assert format_size(1234) == "1.2 KiB"
    assert format_size(1234567) == "1.2 MiB"
    assert format_size(1234567890) == "1.1 GiB" 
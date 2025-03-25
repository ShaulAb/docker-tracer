"""Utility functions for Docker service operations."""

import re
from typing import Dict, List, Optional, Tuple, Union
from enum import Enum

from .models import CommandType, PackageManager, PackageCommand


class PackageManagerPatterns:
    """Regular expression patterns for parsing package specifications by package manager."""
    NPM = r'^([^@]+)@(.+)$'  # express@4.17.1
    PIP = r'^([^=<>!~]+)(==|>=|<=|!=|~=)(\d.+)$'  # requests==2.26.0
    APT = r'^([^=]+)(=.+)$'  # python3=3.9.5-2
    APK = r'^([^=]+)(=.+)$'  # python3=3.9.5-r0
    DNF = r'^([^-]+)-(\d.+)$'  # python3-3.9.5


def parse_command_type(command: str) -> CommandType:
    """Parse the Docker command type from a layer command string.
    
    Args:
        command: The Docker command string (e.g., '/bin/sh -c #(nop) CMD ["python"]')
    
    Returns:
        The corresponding CommandType enum value
    """
    # Handle #(nop) commands
    nop_match = re.search(r'#\(nop\)\s+(\w+)', command)
    if nop_match:
        try:
            return CommandType[nop_match.group(1)]
        except KeyError:
            return CommandType.UNKNOWN

    # Handle RUN commands
    if '/bin/sh -c' in command:
        return CommandType.RUN

    return CommandType.UNKNOWN


def clean_version_string(version: str) -> str:
    """Clean a version string by removing leading non-digits.
    
    Args:
        version: Raw version string that might include operators
    
    Returns:
        Version string starting from the first digit
    """
    # print(f"Input version string: '{version}'")  # Debug
    # Find the first digit in the string
    for i, char in enumerate(version):
        # print(f"Checking char at {i}: '{char}'")  # Debug
        if char.isdigit():
            result = version[i:]
            # print(f"Found first digit at {i}, returning: '{result}'")  # Debug
            return result
    # print("No digits found, returning original")  # Debug
    return version  # Return original if no digits found


def parse_version_constraint(package: str, package_manager: Optional[PackageManager] = None) -> Tuple[str, str]:
    """Parse a package specification into name and version constraint.
    
    Args:
        package: Package specification string (e.g. "requests==2.26.0")
        package_manager: Optional package manager to use specific parsing rules
    
    Returns:
        Tuple of (package_name, version_constraint)
    """
    # print(f"\nParsing package: '{package}'")
    # print(f"Package manager provided: {package_manager}")
    
    # Map package managers to their patterns
    patterns = {
        PackageManager.NPM: PackageManagerPatterns.NPM,  # name@version
        PackageManager.YARN: PackageManagerPatterns.NPM,  # name@version
        PackageManager.PIP: PackageManagerPatterns.PIP,  # name==version
        PackageManager.APT: PackageManagerPatterns.APT,  # name=version
        PackageManager.APT_GET: PackageManagerPatterns.APT,  # name=version
        PackageManager.APK: PackageManagerPatterns.APK,  # name=version
        PackageManager.DNF: PackageManagerPatterns.DNF,  # name-version
        PackageManager.YUM: PackageManagerPatterns.DNF,  # name-version
    }
    
    if package_manager and package_manager in patterns:
        # print(f"Using pattern for {package_manager}: {patterns[package_manager]}")
        pattern = patterns[package_manager]
        match = re.match(pattern, package)
        if match:
            # print(f"Pattern matched groups: {match.groups()}")
            if package_manager in [PackageManager.NPM, PackageManager.YARN]:
                return match.group(1), match.group(2)
            elif package_manager in [PackageManager.APT, PackageManager.APT_GET, PackageManager.APK]:
                name = match.group(1)
                version = clean_version_string(match.group(2))
                # print(f"APT/APK version before cleaning: '{match.group(2)}'")
                # print(f"APT/APK version after cleaning: '{version}'")
                return name, version
            elif package_manager in [PackageManager.DNF, PackageManager.YUM]:
                return match.group(1), match.group(2)
            elif package_manager == PackageManager.PIP:
                name = match.group(1)
                operator = match.group(2)
                version = match.group(3)
                if operator == '==':
                    return name, version
                return name, f"{operator}{version}"
    else:
        print("No package manager provided or not in patterns, falling back to generic parsing")
    
    # Fallback to generic parsing if no specific pattern matched
    # Try PIP style first (handles complex operators like >=, <=, ==)
    pip_match = re.match(PackageManagerPatterns.PIP, package)
    if pip_match:
        print("Matched PIP pattern in fallback")
        name = pip_match.group(1)
        operator = pip_match.group(2)
        version = pip_match.group(3)
        if operator == '==':
            return name, version
        return name, f"{operator}{version}"
    
    # Try APT/APK style (simple equals sign)
    apt_match = re.match(PackageManagerPatterns.APT, package)
    if apt_match:
        print("Matched APT pattern in fallback")
        print(f"APT match groups: {apt_match.groups()}")
        name = apt_match.group(1)
        version = clean_version_string(apt_match.group(2))
        print(f"APT version before cleaning: '{apt_match.group(2)}'")
        print(f"APT version after cleaning: '{version}'")
        return name, version
    
    # Try DNF/YUM style (name-version)
    dnf_match = re.match(PackageManagerPatterns.DNF, package)
    if dnf_match:
        print("Matched DNF pattern in fallback")
        return dnf_match.group(1), dnf_match.group(2)
    
    print("No pattern matched, returning original package")
    # No version constraint found
    return package, ""


def parse_package_command(command: str) -> Optional[PackageCommand]:
    """Parse a package manager command from a Docker RUN command.
    
    Args:
        command: The command string to parse
        
    Returns:
        PackageCommand object if command is a package manager command, None otherwise
    """
    # Normalize command by removing extra whitespace
    command = ' '.join(command.split())
    
    # Check for package manager commands
    for pkg_mgr in PackageManager:
        # Match exact command prefix
        prefix = f"{pkg_mgr.value} "
        if command.startswith(prefix):
            # Extract packages part after the command
            remaining = command[len(prefix):].strip()
            
            # Extract the command (install, update, etc.)
            parts = remaining.split()
            if not parts:
                continue
                
            cmd_type = parts[0]
            
            # Command type normalization
            if (pkg_mgr == PackageManager.APK or pkg_mgr == PackageManager.YARN) and cmd_type == 'add':
                # Keep 'add' as is for APK and YARN
                pass
            elif cmd_type in ['install', 'i']:  # Removed 'add' from this list
                cmd_type = 'install'
            elif cmd_type == 'add':  # Handle non-APK/YARN 'add' separately
                cmd_type = 'install'
            elif cmd_type in ['update', 'up']:
                cmd_type = 'update'
            elif cmd_type in ['upgrade']:
                cmd_type = 'upgrade'
            else:
                continue  # Unknown command type
                
            # Skip the command and any flags at the start
            packages_part = ' '.join(parts[1:])
            
            # Split into individual packages, handling quotes
            packages = []
            current = []
            in_quotes = False
            for char in packages_part:
                if char == '"' or char == "'":
                    in_quotes = not in_quotes
                elif char.isspace() and not in_quotes:
                    if current:
                        packages.append(''.join(current))
                        current = []
                else:
                    current.append(char)
            if current:
                packages.append(''.join(current))
            
            # Parse each package
            parsed_packages = []
            version_constraints = {}
            for pkg in packages:
                # Skip options/flags
                if pkg.startswith('-'):
                    continue
                    
                # Parse package name and version using package manager specific patterns
                name, version = parse_version_constraint(pkg, pkg_mgr)
                if name:
                    parsed_packages.append(name)  # Only store name in packages list
                    if version:  # Store version in constraints dict if present
                        version_constraints[name] = version
            
            if parsed_packages:
                return PackageCommand(
                    manager=pkg_mgr,
                    command=cmd_type,
                    packages=parsed_packages,
                    version_constraints=version_constraints
                )
                
    return None


def parse_image_name(image_name: str) -> Dict[str, str]:
    """Parse a Docker image name into its components.
    
    Args:
        image_name: Docker image name (e.g. 'ubuntu:latest', 'registry.example.com/ubuntu:18.04')
        
    Returns:
        Dict with 'registry', 'repository', and 'tag' keys. If no tag is specified, defaults to 'latest'.
    """
    # Initialize components
    registry = None
    repository = image_name
    tag = 'latest'  # Default tag
    
    # First split on forward slash to separate registry
    parts = repository.split('/', 1)
    if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0] or parts[0] == 'localhost'):
        registry = parts[0]
        repository = parts[1]
    
    # Check for SHA256 digest format (@sha256:...)
    if '@sha256:' in repository:
        repo_parts = repository.split('@sha256:', 1)
        repository = repo_parts[0]
        tag = f'sha256:{repo_parts[1]}'
    # If no SHA256, check for normal tag
    elif ':' in repository:
        repository, tag = repository.rsplit(':', 1)
    
    return {
        'registry': registry,
        'repository': repository,
        'tag': tag
    }


def format_size(size_bytes: int) -> str:
    """Format file size in bytes to human readable string.
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        Formatted string (e.g., '1.23 MiB')
    """
    if size_bytes == 0:
        return "0 B"
        
    units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    i = 0
    size = float(size_bytes)
    
    while size >= 1024.0 and i < len(units) - 1:
        size /= 1024.0
        i += 1
        
    return f"{size:.1f} {units[i]}"

if __name__ == "__main__":
    print("\nTesting with failing case:")
    test_version = "package=1.2.3-1"
    
    print("\nTesting with APT package manager:")
    name, version = parse_version_constraint(test_version, PackageManager.APT)
    print(f"Final result with APT: name='{name}', version='{version}'")
    assert version == "1.2.3-1", f"Expected '1.2.3-1' but got '{version}'"
    
    print("\nTesting with fallback:")
    name, version = parse_version_constraint(test_version)
    print(f"Final result with fallback: name='{name}', version='{version}'")
    assert version == "1.2.3-1", f"Expected '1.2.3-1' but got '{version}'" 
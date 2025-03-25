"""Utility functions for Docker service operations."""

import re
import shlex
from typing import Dict, List, Optional, Tuple, Union
from enum import Enum

from .models import CommandType, PackageManager, PackageCommand


# Package manager command patterns
PACKAGE_PATTERNS = {
    PackageManager.APT: [
        # Match apt-get install with flags and multiple packages
        r'apt-get\s+install\s+(?:-[^\s]*\s+)*(?:--[^\s]*\s+)*([^;|&]+)',
        r'apt\s+install\s+(?:-[^\s]*\s+)*(?:--[^\s]*\s+)*([^;|&]+)'
    ],
    PackageManager.PIP: [
        # Match pip install with various flags and options
        r'pip[23]?\s+install\s+(?:--[^\s]*\s+)*([^;|&]+)',
        r'python[23]?\s+-m\s+pip\s+install\s+(?:--[^\s]*\s+)*([^;|&]+)'
    ],
    PackageManager.YUM: [
        r'yum\s+install\s+(?:-[^\s]*\s+)*(?:--[^\s]*\s+)*([^;|&]+)',
    ],
    PackageManager.DNF: [
        r'dnf\s+install\s+(?:-[^\s]*\s+)*(?:--[^\s]*\s+)*([^;|&]+)',
    ],
    PackageManager.APK: [
        r'apk\s+add\s+(?:-[^\s]*\s+)*(?:--[^\s]*\s+)*([^;|&]+)',
    ],
    PackageManager.NPM: [
        r'npm\s+install\s+(?:--[^\s]*\s+)*([^;|&]+)',
    ],
    PackageManager.YARN: [
        r'yarn\s+add\s+(?:--[^\s]*\s+)*([^;|&]+)',
    ]
}

def split_shell_commands(command: str) -> List[str]:
    """Split a complex shell command into individual commands.
    
    Args:
        command: Complex shell command string
        
    Returns:
        List of individual commands
    """
    # Remove shell prefixes and set commands
    command = re.sub(r'^/bin/sh\s+-c\s+', '', command)
    command = re.sub(r'^set\s+-[eux]+;\s*', '', command)
    
    # Split on common shell operators while preserving quoted strings
    commands = []
    current_cmd = []
    tokens = shlex.split(command)
    
    for token in tokens:
        if token in ['&&', '||', ';']:
            if current_cmd:
                commands.append(' '.join(current_cmd))
                current_cmd = []
        else:
            current_cmd.append(token)
    
    if current_cmd:
        commands.append(' '.join(current_cmd))
    
    # Further split commands if they contain multiple package operations
    final_commands = []
    for cmd in commands:
        # Split on pipe operators but preserve the command structure
        parts = re.split(r'\s*\|\s*', cmd)
        final_commands.extend(parts)
    
    return [cmd.strip() for cmd in final_commands if cmd.strip()]

def extract_package_patterns(command: str) -> List[Tuple[PackageManager, str, List[str]]]:
    """Extract package manager commands and packages using regex patterns.
    
    Args:
        command: Command string to analyze
        
    Returns:
        List of tuples (package_manager, command_type, package_list)
    """
    # print(f"\nAnalyzing command: {command}")  # Debug
    results = []
    
    for pkg_mgr, patterns in PACKAGE_PATTERNS.items():
        for pattern in patterns:
            if match := re.search(pattern, command):
                # print(f"Matched pattern for {pkg_mgr}: {pattern}")  # Debug
                packages_str = match.group(1).strip()
                # print(f"Found packages string: {packages_str}")  # Debug
                # Split packages, handling quotes and removing flags
                raw_packages = shlex.split(packages_str)
                # print(f"Raw packages: {raw_packages}")  # Debug
                packages = []
                for pkg in raw_packages:
                    # Skip flags and options
                    if pkg.startswith('-') or pkg.startswith('--'):
                        continue
                    # Skip package manager commands that might be in the list
                    if any(cmd in pkg.lower() for cmd in ['install', 'update', 'remove', 'purge']):
                        continue
                    packages.append(pkg)
                
                # print(f"Final packages: {packages}")  # Debug
                if packages:  # Only add if we found actual packages
                    # Determine command type (install, add, etc.)
                    cmd_type = 'install'  # Default
                    if pkg_mgr in [PackageManager.APK, PackageManager.YARN] and 'add' in command:
                        cmd_type = 'add'
                    results.append((pkg_mgr, cmd_type, packages))
    
    # if not results:
    #     print("No pattern matched")  # Debug
    return results

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

    # Handle RUN commands - more permissive matching
    if any(pattern in command for pattern in ['/bin/sh -c', 'RUN ', '/bin/bash -c']):
        return CommandType.RUN
        
    # If the command contains package manager commands, treat it as RUN
    package_managers = ['apt-get', 'apt', 'pip', 'pip3', 'npm', 'yarn', 'yum', 'dnf', 'apk']
    if any(pm in command.lower() for pm in package_managers):
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
    
    # print("No pattern matched, returning original package")
    # No version constraint found
    return package, ""


def parse_package_command(command: str) -> Optional[PackageCommand]:
    """Parse a package manager command from a Docker RUN command.
    
    Args:
        command: The command string to parse
        
    Returns:
        PackageCommand object if command is a package manager command, None otherwise
    """
    # Split complex commands into individual ones
    commands = split_shell_commands(command)
    
    for cmd in commands:
        # Try pattern-based detection first
        package_matches = extract_package_patterns(cmd)
        if package_matches:
            pkg_mgr, cmd_type, packages = package_matches[0]  # Take first match
            # Parse version constraints for each package
            version_constraints = {}
            for pkg in packages:
                name, version = parse_version_constraint(pkg, pkg_mgr)
                if version:
                    version_constraints[name] = version
            
            return PackageCommand(
                manager=pkg_mgr,
                command=cmd_type,
                packages=packages,
                version_constraints=version_constraints
            )
    
    # If no matches found with patterns, try the original exact command matching
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
            elif cmd_type in ['install', 'i']:
                cmd_type = 'install'
            elif cmd_type in ['update', 'up']:
                cmd_type = 'update'
            elif cmd_type in ['upgrade']:
                cmd_type = 'upgrade'
            else:
                continue  # Unknown command type
                
            # Skip the command and any flags
            packages_part = ' '.join(parts[1:])
            packages = shlex.split(packages_part)
            
            # Parse version constraints
            version_constraints = {}
            for pkg in packages:
                name, version = parse_version_constraint(pkg, pkg_mgr)
                if version:
                    version_constraints[name] = version
            
            return PackageCommand(
                manager=pkg_mgr,
                command=cmd_type,
                packages=packages,
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
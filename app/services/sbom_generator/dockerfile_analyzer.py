"""Dockerfile analyzer for SBOM generation and image matching."""

import logging
import re
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class DockerInstruction:
    """Represents a parsed Dockerfile instruction."""
    type: str  # FROM, RUN, COPY, etc.
    content: str  # Raw instruction content
    line_number: int
    args: List[str]  # Parsed arguments

@dataclass
class DockerfileAnalysis:
    """Results of Dockerfile analysis."""
    base_image: str
    stages: List[str]  # For multi-stage builds
    package_commands: List[DockerInstruction]  # Package installation commands
    copy_commands: List[DockerInstruction]  # File copy operations
    all_instructions: List[DockerInstruction]
    metadata: Dict[str, str]  # Labels, etc.

class DockerfileAnalyzer:
    """Analyzes Dockerfiles to extract build information and dependencies."""

    # Common package manager commands
    PACKAGE_INSTALL_PATTERNS = [
        r'apt-get\s+install',
        r'apk\s+add',
        r'yum\s+install',
        r'dnf\s+install',
        r'pip\s+install',
        r'npm\s+install',
        r'gem\s+install'
    ]

    def __init__(self):
        """Initialize the Dockerfile analyzer."""
        self.install_pattern = re.compile('|'.join(self.PACKAGE_INSTALL_PATTERNS))

    def analyze_file(self, dockerfile_path: str) -> DockerfileAnalysis:
        """Analyze a Dockerfile and extract build information.
        
        Args:
            dockerfile_path: Path to the Dockerfile
            
        Returns:
            DockerfileAnalysis: Analysis results
            
        Raises:
            FileNotFoundError: If Dockerfile doesn't exist
            ValueError: If Dockerfile is invalid
        """
        if not Path(dockerfile_path).exists():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")

        with open(dockerfile_path, 'r') as f:
            content = f.read()

        return self.analyze_content(content)

    def analyze_content(self, content: str) -> DockerfileAnalysis:
        """Analyze Dockerfile content and extract build information.
        
        Args:
            content: Dockerfile content as string
            
        Returns:
            DockerfileAnalysis: Analysis results
            
        Raises:
            ValueError: If Dockerfile content is invalid
        """
        instructions = self._parse_instructions(content)
        if not instructions:
            raise ValueError("No valid instructions found in Dockerfile")

        # Extract base image from first FROM instruction
        base_image = ""
        stages = []
        for inst in instructions:
            if inst.type == "FROM":
                if " as " in inst.content.lower():
                    stage = inst.content.lower().split(" as ")[1].strip()
                    stages.append(stage)
                base_image = inst.args[0]
                break

        if not base_image:
            raise ValueError("No base image (FROM instruction) found in Dockerfile")

        # Collect package and copy instructions
        package_commands = []
        copy_commands = []
        metadata = {}

        for inst in instructions:
            if inst.type == "RUN" and self._is_package_install(inst.content):
                package_commands.append(inst)
            elif inst.type in ["COPY", "ADD"]:
                copy_commands.append(inst)
            elif inst.type == "LABEL":
                self._parse_labels(inst.args[0], metadata)

        return DockerfileAnalysis(
            base_image=base_image,
            stages=stages,
            package_commands=package_commands,
            copy_commands=copy_commands,
            all_instructions=instructions,
            metadata=metadata
        )

    def _parse_instructions(self, content: str) -> List[DockerInstruction]:
        """Parse Dockerfile content into instructions.
        
        Args:
            content: Dockerfile content
            
        Returns:
            List[DockerInstruction]: Parsed instructions
        """
        instructions = []
        current_instruction = []
        line_number = 0

        for line in content.splitlines():
            line_number += 1
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Handle line continuations
            if line.endswith('\\'):
                current_instruction.append(line[:-1].strip())
                continue

            current_instruction.append(line)
            
            # Process complete instruction
            if current_instruction:
                full_instruction = ' '.join(current_instruction)
                instruction = self._parse_single_instruction(full_instruction, line_number)
                if instruction:
                    instructions.append(instruction)
                current_instruction = []

        return instructions

    def _parse_single_instruction(self, content: str, line_number: int) -> Optional[DockerInstruction]:
        """Parse a single Dockerfile instruction.
        
        Args:
            content: Instruction content
            line_number: Line number in Dockerfile
            
        Returns:
            Optional[DockerInstruction]: Parsed instruction or None if invalid
        """
        parts = content.split(maxsplit=1)
        if not parts:
            return None

        instruction_type = parts[0].upper()
        args_str = parts[1] if len(parts) > 1 else ""

        # Parse arguments based on instruction type
        if instruction_type in ["RUN", "LABEL", "ENV"]:
            args = [args_str]
        else:
            # Handle special case for COPY with --from
            if instruction_type == "COPY" and "--from=" in args_str:
                args = args_str.split()
            else:
                args = [arg.strip() for arg in args_str.split()]

        return DockerInstruction(
            type=instruction_type,
            content=content,
            line_number=line_number,
            args=args
        )

    def _is_package_install(self, command: str) -> bool:
        """Check if a RUN command is installing packages.
        
        Args:
            command: Command string
            
        Returns:
            bool: True if command is installing packages
        """
        return bool(self.install_pattern.search(command.lower()))

    def _parse_labels(self, content: str, metadata: Dict[str, str]):
        """Parse LABEL instruction into metadata dictionary.
        
        Args:
            content: Label content
            metadata: Metadata dictionary to update
        """
        # Handle both space-separated and '=' format
        if '=' in content:
            # Handle key=value format
            parts = content.split('=', 1)
            key = parts[0].strip()
            value = parts[1].strip().strip('"\'')
            metadata[key.lower()] = value
        else:
            # Handle space-separated format
            parts = content.split()
            for i in range(0, len(parts) - 1, 2):
                key = parts[i].strip()
                value = parts[i + 1].strip().strip('"\'')
                metadata[key.lower()] = value 
"""Utilities for handling Docker command normalization and comparison."""
from dataclasses import dataclass
from typing import List, Union, Optional
import ast
import shlex
from pathlib import Path
from loguru import logger


@dataclass
class NormalizedCommand:
    """Normalized representation of a Docker command."""
    executable: str
    args: List[str]
    is_shell_form: bool
    shell_command: Optional[str] = None  # The actual command when using shell -c

    def __str__(self) -> str:
        if self.shell_command:
            return f"{self.executable} -c '{self.shell_command}'"
        if not self.args:
            return self.executable
        return f"{self.executable} {' '.join(self.args)}"


class DockerCommandNormalizer:
    """Handles normalization and comparison of Docker commands."""
    
    SHELL_COMMANDS = {'/bin/sh', '/bin/bash', 'sh', 'bash'}

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a command path by extracting the base command name."""
        return Path(path).name

    @staticmethod
    def _normalize_args(args: List[str]) -> List[str]:
        """Normalize command arguments, handling paths and special cases."""
        normalized = []
        for arg in args:
            # Skip empty args
            if not arg:
                continue
            # Handle path-like arguments
            if '/' in arg:
                arg = DockerCommandNormalizer._normalize_path(arg)
            normalized.append(arg.strip())
        return normalized

    @staticmethod
    def _extract_shell_command(executable: str, args: List[str]) -> Optional[str]:
        """Extract the actual command when using shell -c."""
        norm_exec = DockerCommandNormalizer._normalize_path(executable)
        if norm_exec in DockerCommandNormalizer.SHELL_COMMANDS and len(args) >= 2:
            if args[0] == '-c':
                # Join all remaining args as they form the shell command
                return ' '.join(args[1:])
        return None

    @staticmethod
    def _parse_shell_command(cmd: str) -> tuple[str, List[str], Optional[str]]:
        """Parse a shell command using shlex to handle quotes properly."""
        try:
            parts = shlex.split(cmd)
            if not parts:
                return "", [], None
                
            executable = parts[0]
            args = parts[1:]
            
            # Special handling for shell -c commands
            shell_cmd = DockerCommandNormalizer._extract_shell_command(executable, args)
            if shell_cmd:
                # For shell commands, keep the -c and the full command as args
                return executable, ['-c', shell_cmd], shell_cmd
                
            return executable, args, None
            
        except ValueError as e:
            logger.warning(f"Failed to parse shell command: {e}")
            # Fallback to simple splitting
            parts = cmd.split()
            executable = parts[0] if parts else ""
            args = parts[1:] if len(parts) > 1 else []
            shell_cmd = DockerCommandNormalizer._extract_shell_command(executable, args)
            if shell_cmd:
                return executable, ['-c', shell_cmd], shell_cmd
            return executable, args, None

    @staticmethod
    def _try_parse_json_string(cmd: str) -> Optional[Union[str, List[str]]]:
        """Try to parse a JSON string into a command."""
        try:
            parsed = ast.literal_eval(cmd)
            if isinstance(parsed, (str, list)):
                return parsed
            return None
        except (ValueError, SyntaxError):
            return None

    @staticmethod
    def normalize(cmd: Union[str, List[str], None]) -> NormalizedCommand:
        """Convert any Docker command format to normalized structure.
        
        Args:
            cmd: Command in string, list, or None format
            
        Returns:
            NormalizedCommand with parsed executable and args
        """
        if cmd is None:
            return NormalizedCommand("", [], False)
            
        # Handle list format first to unwrap any nested JSON strings
        if isinstance(cmd, list):
            if not cmd:
                return NormalizedCommand("", [], False)
                
            logger.debug(f"Processing list command: {cmd}")
            
            # If we have a single-item list with a JSON string, parse it
            if len(cmd) == 1 and isinstance(cmd[0], str):
                parsed = DockerCommandNormalizer._try_parse_json_string(cmd[0])
                if parsed is not None:
                    logger.debug(f"Unwrapped JSON string from list: {parsed}")
                    # Recursively normalize the parsed result
                    return DockerCommandNormalizer.normalize(parsed)
            
            # Regular list processing
            executable = str(cmd[0]).strip()
            args = [str(arg).strip() for arg in cmd[1:]]
            shell_cmd = DockerCommandNormalizer._extract_shell_command(executable, args)
            if shell_cmd:
                args = ['-c', shell_cmd]
            return NormalizedCommand(
                executable=executable,
                args=args,
                is_shell_form=False,
                shell_command=shell_cmd
            )
            
        # Handle string format
        if isinstance(cmd, str):
            # Try to parse as array first
            cmd = cmd.strip()
            if cmd.startswith("[") and cmd.endswith("]"):
                parsed = DockerCommandNormalizer._try_parse_json_string(cmd)
                if parsed is not None:
                    logger.debug(f"Successfully parsed array command: {cmd} -> {parsed}")
                    # Recursively normalize the parsed result
                    return DockerCommandNormalizer.normalize(parsed)
                    
            # If not array or parsing failed, treat as shell form
            executable, args, shell_cmd = DockerCommandNormalizer._parse_shell_command(cmd)
            logger.debug(f"Parsed shell command: {cmd} -> executable={executable}, args={args}, shell_cmd={shell_cmd}")
            return NormalizedCommand(
                executable=executable,
                args=args,
                is_shell_form=True,
                shell_command=shell_cmd
            )
            
        # Handle unexpected types
        logger.warning(f"Unexpected command type: {type(cmd)}")
        return NormalizedCommand("", [], False)

    @staticmethod
    def commands_equal(cmd1: NormalizedCommand, cmd2: NormalizedCommand, ignore_path: bool = True) -> bool:
        """Compare two normalized commands for equality.
        
        Args:
            cmd1: First normalized command
            cmd2: Second normalized command
            ignore_path: If True, compare only base command names
            
        Returns:
            True if commands are equivalent, False otherwise
        """
        logger.debug(f"Comparing commands: {cmd1} vs {cmd2}")
        
        # If both empty, they match
        if not cmd1.executable and not cmd2.executable:
            logger.debug("Both commands empty - match")
            return True

        # Compare executables first
        exec1 = DockerCommandNormalizer._normalize_path(cmd1.executable) if ignore_path else cmd1.executable
        exec2 = DockerCommandNormalizer._normalize_path(cmd2.executable) if ignore_path else cmd2.executable
        
        if exec1.strip() != exec2.strip():
            logger.debug(f"Executable mismatch: {exec1} != {exec2}")
            return False

        # If both are shell commands, compare the shell_command
        if cmd1.shell_command and cmd2.shell_command:
            match = cmd1.shell_command.strip() == cmd2.shell_command.strip()
            if match:
                logger.debug(f"Shell commands match: {cmd1.shell_command}")
            else:
                logger.debug(f"Shell command mismatch: {cmd1.shell_command} != {cmd2.shell_command}")
            return match
            
        # If one has shell_command but other doesn't, they don't match
        if cmd1.shell_command or cmd2.shell_command:
            logger.debug("One command is shell form but other isn't")
            return False
            
        # Compare normalized args
        args1 = DockerCommandNormalizer._normalize_args(cmd1.args)
        args2 = DockerCommandNormalizer._normalize_args(cmd2.args)
        
        if len(args1) != len(args2):
            logger.debug(f"Args length mismatch: {len(args1)} != {len(args2)}")
            return False
            
        match = all(a1 == a2 for a1, a2 in zip(args1, args2))
        if match:
            logger.debug("Commands match exactly")
        else:
            logger.debug(f"Args mismatch: {args1} != {args2}")
        return match 
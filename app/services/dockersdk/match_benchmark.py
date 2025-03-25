"""Benchmark system for Dockerfile to Docker image matching."""

import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import docker
from loguru import logger

from app.services.sbom_generator.container_analyzer import DockerImageInspector
from app.services.sbom_generator.dockerfile_analyzer import DockerfileAnalyzer, DockerInstruction
from .command_utils import DockerCommandNormalizer

@dataclass
class MatchScore:
    """Represents the matching score between a Dockerfile and image."""
    overall_score: float
    environment_score: float
    ports_score: float
    commands_score: float
    layers_score: float
    platform_score: float
    workdir_score: float
    volumes_score: float
    details: Dict[str, str]  # Detailed explanations for each score

class DockerfileImageMatcher:
    """Matches Dockerfiles with their corresponding images."""
    
    def __init__(self):
        """Initialize the matcher."""
        self.image_inspector = DockerImageInspector()
        self.dockerfile_analyzer = DockerfileAnalyzer()
        
    async def calculate_match_score(
        self,
        dockerfile_analysis: Dict,
        image_analysis: Dict
    ) -> MatchScore:
        """Calculate how well a Dockerfile matches an image."""
        # Extract config from image analysis
        image_config = image_analysis.get("Config", {})
        
        # Calculate individual scores with explanations
        env_score, env_details = self._score_environment(
            dockerfile_analysis.get("environment", {}),
            image_config.get("Env", [])
        )
        
        ports_score, ports_details = self._score_ports(
            dockerfile_analysis.get("exposed_ports", []),
            image_config.get("ExposedPorts", {})
        )
        
        cmd_score, cmd_details = self._score_commands(
            dockerfile_analysis.get("instructions", []),
            image_config
        )
        
        layers_score, layers_details = self._score_layers(
            dockerfile_analysis.get("instructions", []),
            image_analysis.get("History", [])
        )
        
        platform_score, platform_details = self._score_platform(
            dockerfile_analysis.get("base_image", ""),
            image_analysis.get("Architecture", "")
        )
        
        workdir_score, workdir_details = self._score_workdir(
            dockerfile_analysis.get("instructions", []),
            image_config.get("WorkingDir", "")
        )
        
        # Handle None case for Volumes
        image_volumes = image_config.get("Volumes")
        volumes_list = list(image_volumes.keys()) if image_volumes is not None else []
        
        volumes_score, volumes_details = self._score_volumes(
            dockerfile_analysis.get("volumes", []),
            volumes_list
        )
        
        # Calculate weighted overall score
        weights = {
            "environment": 0.15,
            "ports": 0.10,
            "commands": 0.15,
            "layers": 0.30,
            "platform": 0.10,
            "workdir": 0.10,
            "volumes": 0.10
        }
        
        overall_score = sum([
            env_score * weights["environment"],
            ports_score * weights["ports"],
            cmd_score * weights["commands"],
            layers_score * weights["layers"],
            platform_score * weights["platform"],
            workdir_score * weights["workdir"],
            volumes_score * weights["volumes"]
        ])
        
        return MatchScore(
            overall_score=overall_score,
            environment_score=env_score,
            ports_score=ports_score,
            commands_score=cmd_score,
            layers_score=layers_score,
            platform_score=platform_score,
            workdir_score=workdir_score,
            volumes_score=volumes_score,
            details={
                "environment": env_details,
                "ports": ports_details,
                "commands": cmd_details,
                "layers": layers_details,
                "platform": platform_details,
                "workdir": workdir_details,
                "volumes": volumes_details
            }
        )
    
    def _score_environment(
        self,
        dockerfile_env: Dict[str, str],
        image_env: List[str]
    ) -> Tuple[float, str]:
        """Score environment variable matching."""
        if not dockerfile_env and not image_env:
            return 1.0, "No environment variables in either"
            
        if not dockerfile_env or not image_env:
            return 0.0, "Environment variables in only one source"
            
        # Convert image env list to dict
        image_env_dict = {}
        for env in image_env:
            if '=' in env:
                key, value = env.split('=', 1)
                image_env_dict[key.strip()] = value.strip()
        
        # Count matches
        matches = 0
        total = len(dockerfile_env)
        details = []
        
        for key, value in dockerfile_env.items():
            if key in image_env_dict:
                if image_env_dict[key] == value:
                    matches += 1
                    details.append(f"Exact match: {key}={value}")
                else:
                    matches += 0.5
                    details.append(f"Key match with different value: {key}")
                    
        score = matches / total if total > 0 else 0.0
        if not details:
            details.append("No matching environment variables")
        return score, "; ".join(details)
    
    def _score_ports(
        self,
        dockerfile_ports: List[str],
        image_ports: Optional[Dict[str, Dict]]
    ) -> Tuple[float, str]:
        """Score exposed port matching."""
        # Handle None case for image_ports
        if image_ports is None:
            image_ports = {}
            
        if not dockerfile_ports and not image_ports:
            return 1.0, "No ports exposed in either"
            
        if not dockerfile_ports or not image_ports:
            return 0.0, "Ports exposed in only one source"
        
        # Normalize port format (handle tcp/udp)
        def normalize_port(port: str) -> str:
            # If port has protocol, use it
            if '/' in port:
                return port
            # Docker defaults to TCP if no protocol specified
            return f"{port}/tcp"
            
        # Convert Dockerfile ports to Docker format
        dockerfile_ports_norm = set()
        for port in dockerfile_ports:
            norm_port = normalize_port(port)
            # Docker API expects port as string with protocol
            dockerfile_ports_norm.add(norm_port)
        
        # Get normalized image ports
        image_ports_norm = set(image_ports.keys())
        
        # Calculate intersection
        matches = len(dockerfile_ports_norm & image_ports_norm)
        total = len(dockerfile_ports_norm)
        
        score = matches / total if total > 0 else 0.0
        details = []
        if matches > 0:
            details.append(f"Matched {matches} of {total} ports")
            for port in (dockerfile_ports_norm & image_ports_norm):
                details.append(f"Matched port: {port}")
        else:
            details.append("No matching ports")
            details.append(f"Dockerfile ports: {', '.join(sorted(dockerfile_ports_norm))}")
            details.append(f"Image ports: {', '.join(sorted(image_ports_norm))}")
        return score, "; ".join(details)
    
    def _score_commands(
        self,
        dockerfile_instructions: List[Dict],
        image_config: Dict
    ) -> Tuple[float, str]:
        """Score command (CMD/ENTRYPOINT) matching."""
        normalizer = DockerCommandNormalizer()
        details = []
        
        # Extract commands from Dockerfile
        dockerfile_cmd = None
        dockerfile_entrypoint = None
        for inst in dockerfile_instructions:
            if inst["type"] == "CMD":
                dockerfile_cmd = inst["args"]
            elif inst["type"] == "ENTRYPOINT":
                dockerfile_entrypoint = inst["args"]
                
        # Extract commands from image
        image_cmd = image_config.get("Cmd")
        image_entrypoint = image_config.get("Entrypoint")
        
        # Log raw values for debugging
        logger.debug(f"Dockerfile CMD: {dockerfile_cmd}")
        logger.debug(f"Image CMD: {image_cmd}")
        logger.debug(f"Dockerfile ENTRYPOINT: {dockerfile_entrypoint}")
        logger.debug(f"Image ENTRYPOINT: {image_entrypoint}")
        
        # Normalize all commands
        df_cmd_norm = normalizer.normalize(dockerfile_cmd)
        df_entry_norm = normalizer.normalize(dockerfile_entrypoint)
        img_cmd_norm = normalizer.normalize(image_cmd)
        img_entry_norm = normalizer.normalize(image_entrypoint)
        
        # Compare commands
        cmd_matches = normalizer.commands_equal(df_cmd_norm, img_cmd_norm)
        entrypoint_matches = normalizer.commands_equal(df_entry_norm, img_entry_norm)
        
        # Calculate score (50% weight for each command type)
        score = 0.0
        if cmd_matches:
            score += 0.5
            details.append("CMD matches")
        else:
            details.append(f"Dockerfile CMD: {df_cmd_norm}; Image CMD: {img_cmd_norm}")
            
        if entrypoint_matches:
            score += 0.5
            details.append("ENTRYPOINT matches")
        else:
            details.append(f"Dockerfile ENTRYPOINT: {df_entry_norm}; Image ENTRYPOINT: {img_entry_norm}")
            
        if not details:
            details.append("No command matches")
            
        return score, "; ".join(details)
    
    def _score_layers(
        self,
        dockerfile_instructions: List[Dict],
        image_history: List[Dict]
    ) -> Tuple[float, str]:
        """Score layer history matching."""
        if not dockerfile_instructions or not image_history:
            return 0.0, "Missing layer information"
            
        # Filter relevant instructions that create layers
        layer_instructions = [
            inst for inst in dockerfile_instructions
            if inst["type"] in ("RUN", "COPY", "ADD")
        ]
        
        if not layer_instructions:
            return 1.0, "No layer-creating instructions to match"
        
        # Clean up and normalize history commands
        def normalize_command(cmd: str) -> str:
            """Normalize a command for comparison."""
            # Remove BuildKit markers
            if "#(nop)" in cmd:
                cmd = cmd.split("#(nop)", 1)[1]
            
            # Remove shell prefix
            if cmd.startswith("/bin/sh -c "):
                cmd = cmd[11:]
            
            # Remove quotes if present
            cmd = cmd.strip()
            if (cmd.startswith('"') and cmd.endswith('"')) or (cmd.startswith("'") and cmd.endswith("'")):
                cmd = cmd[1:-1]
            
            return cmd.strip()
        
        # Process history commands with their indices
        history_commands = []
        for idx, h in enumerate(image_history):
            if h.get("created_by"):
                cmd = normalize_command(h["created_by"])
                if cmd:  # Skip empty commands
                    history_commands.append((idx, cmd))
        
        # Track matches and their sequence
        matches = []
        matched_history_indices = set()
        details = []
        
        # Weight different command types
        type_weights = {
            "RUN": 1.0,  # Full weight for RUN commands
            "COPY": 0.8, # Slightly lower for COPY/ADD due to path variations
            "ADD": 0.8
        }
        
        # Try to match instructions in sequence
        for inst_idx, inst in enumerate(layer_instructions):
            inst_value = normalize_command(inst["value"])
            best_match_score = 0
            best_match_idx = -1
            
            # Look for best match in history
            for hist_idx, hist_cmd in history_commands:
                if hist_idx in matched_history_indices:
                    continue
                
                # Calculate command similarity
                if inst["type"] == "RUN":
                    # For RUN commands, use token-based comparison
                    inst_tokens = set(inst_value.split())
                    hist_tokens = set(hist_cmd.split())
                    if inst_tokens and hist_tokens:
                        similarity = len(inst_tokens & hist_tokens) / len(inst_tokens | hist_tokens)
                    else:
                        similarity = 0
                else:
                    # For COPY/ADD, use path-based comparison
                    similarity = 1.0 if inst_value == hist_cmd else 0.0
                
                # Consider sequence in scoring
                sequence_penalty = abs(inst_idx - hist_idx) / len(history_commands)
                match_score = similarity * (1 - sequence_penalty * 0.5)  # Sequence affects up to 50% of score
                
                if match_score > best_match_score:
                    best_match_score = match_score
                    best_match_idx = hist_idx
            
            # Record the match if good enough
            if best_match_score >= 0.5:  # Threshold for considering a match
                matches.append(best_match_score * type_weights[inst["type"]])
                matched_history_indices.add(best_match_idx)
                details.append(f"Matched: {inst_value[:50]}... (score: {best_match_score:.2f})")
            else:
                details.append(f"No match found for: {inst_value[:50]}...")
        
        # Calculate final score
        if not matches:
            return 0.0, "No layer matches found"
        
        score = sum(matches) / len(layer_instructions)  # Normalize by total instructions
        return score, "; ".join(details)
    
    def _score_platform(
        self,
        dockerfile_platform: str,
        image_arch: str
    ) -> Tuple[float, str]:
        """Score platform/architecture matching."""
        if not image_arch:
            return 0.0, "Missing image architecture information"
            
        # Extract architecture from platform string
        dockerfile_arch = None
        
        # Handle platform specification in base image
        if "(" in dockerfile_platform and ")" in dockerfile_platform:
            platform_part = dockerfile_platform.split("(")[1].split(")")[0]
            if "linux/amd64" in platform_part.lower():
                dockerfile_arch = "amd64"
            elif "linux/arm64" in platform_part.lower():
                dockerfile_arch = "arm64"
        
        # If no platform specified, try to infer from base image
        if not dockerfile_arch:
            if "amd64" in dockerfile_platform.lower():
                dockerfile_arch = "amd64"
            elif "arm64" in dockerfile_platform.lower():
                dockerfile_arch = "arm64"
            else:
                # Default to image architecture if no platform specified
                dockerfile_arch = image_arch
                
        # Normalize architectures
        arch_mapping = {
            "amd64": ["amd64", "x86_64"],
            "arm64": ["arm64", "aarch64"]
        }
        
        # Check if architectures match
        for arch_family, variants in arch_mapping.items():
            if dockerfile_arch in variants and image_arch in variants:
                return 1.0, f"Architecture match: {arch_family}"
                
        return 0.0, f"Architecture mismatch: Dockerfile={dockerfile_arch}, Image={image_arch}"
    
    def _score_workdir(
        self,
        dockerfile_instructions: List[Dict],
        image_workdir: str
    ) -> Tuple[float, str]:
        """Score working directory matching."""
        if not dockerfile_instructions:
            return 0.0, "No Dockerfile instructions"
            
        # Get final WORKDIR from Dockerfile
        final_workdir = None
        for inst in reversed(dockerfile_instructions):
            if inst["type"] == "WORKDIR":
                final_workdir = inst["value"]
                break
                
        if not final_workdir:
            return 1.0 if not image_workdir else 0.0, "No WORKDIR specified"
            
        # Compare working directories
        if final_workdir == image_workdir:
            return 1.0, "Exact WORKDIR match"
        elif final_workdir.rstrip('/') == image_workdir.rstrip('/'):
            return 0.9, "WORKDIR match (ignoring trailing slash)"
            
        return 0.0, "WORKDIR mismatch"
    
    def _score_volumes(
        self,
        dockerfile_volumes: List[str],
        image_volumes: List[str]
    ) -> Tuple[float, str]:
        """Score volume matching."""
        if not dockerfile_volumes and not image_volumes:
            return 1.0, "No volumes in either"
            
        if not dockerfile_volumes or not image_volumes:
            return 0.0, "Volumes in only one source"
            
        # Normalize volume paths
        def normalize_volume(vol: str) -> str:
            return vol.rstrip('/')
            
        dockerfile_vols_norm = {normalize_volume(v) for v in dockerfile_volumes}
        image_vols_norm = {normalize_volume(v) for v in image_volumes}
        
        # Calculate intersection
        matches = len(dockerfile_vols_norm & image_vols_norm)
        total = len(dockerfile_vols_norm)
        
        score = matches / total if total > 0 else 0.0
        details = f"Matched {matches} of {total} volumes"
        return score, details

class BenchmarkRunner:
    """Runs benchmarks for Dockerfile-Image matching."""
    
    def __init__(self):
        """Initialize the benchmark runner."""
        self.matcher = DockerfileImageMatcher()
        
    async def run_benchmark(
        self,
        dockerfile_path: str,
        image_ref: str
    ) -> MatchScore:
        """Run a benchmark test for a Dockerfile-Image pair."""
        # Analyze Dockerfile
        dockerfile_analyzer = DockerfileAnalyzer()
        analysis = dockerfile_analyzer.analyze_file(dockerfile_path)
        
        # Extract platform from base image if specified
        base_image = analysis.base_image
        platform = ""
        for inst in analysis.all_instructions:
            if inst.type == "FROM":
                if "--platform=" in inst.content:
                    platform = inst.content.split("--platform=")[1].split()[0]
                break
        
        # Convert analysis to the format expected by the matcher
        dockerfile_analysis = {
            "base_image": f"{base_image} ({platform})" if platform else base_image,
            "environment": {},  # Will be populated from ENV instructions
            "exposed_ports": [],  # Will be populated from EXPOSE instructions
            "volumes": [],  # Will be populated from VOLUME instructions
            "instructions": []  # Will contain all instructions
        }
        
        # Process each instruction
        for inst in analysis.all_instructions:
            # Add to instructions list
            dockerfile_analysis["instructions"].append({
                "type": inst.type,
                "value": inst.content,
                "line_number": inst.line_number,
                "args": inst.args
            })
            
            # Handle specific instruction types
            if inst.type == "ENV":
                # Handle both ENV formats: ENV key=value and ENV key value
                if "=" in inst.args[0]:
                    key, value = inst.args[0].split("=", 1)
                    dockerfile_analysis["environment"][key.strip()] = value.strip()
                elif len(inst.args) >= 2:
                    dockerfile_analysis["environment"][inst.args[0].strip()] = inst.args[1].strip()
            
            elif inst.type == "EXPOSE":
                # Handle port specifications with optional protocol
                for port in inst.args:
                    if "/" not in port:
                        port = f"{port}/tcp"
                    dockerfile_analysis["exposed_ports"].append(port)
            
            elif inst.type == "VOLUME":
                # Handle volume paths
                dockerfile_analysis["volumes"].extend(
                    vol.strip('"\'') for vol in inst.args
                )
        
        # Analyze image
        image_inspector = DockerImageInspector()
        image_analysis = await image_inspector.inspect_image(image_ref)
        
        # Calculate match score
        return await self.matcher.calculate_match_score(
            dockerfile_analysis,
            image_analysis
        )

async def main():
    """Run benchmark examples."""
    benchmark = BenchmarkRunner()
    
    # Example test cases
    test_cases = [
        ("Dockerfile.example", "python:3.9-slim"),
        # Add more test cases here
    ]
    
    for dockerfile, image in test_cases:
        try:
            print(f"\nBenchmarking {dockerfile} against {image}")
            print("=" * 50)
            
            score = await benchmark.run_benchmark(dockerfile, image)
            
            print(f"Overall Score: {score.overall_score:.2%}")
            print("\nDetailed Scores:")
            print(f"Environment: {score.environment_score:.2%}")
            print(f"Ports: {score.ports_score:.2%}")
            print(f"Commands: {score.commands_score:.2%}")
            print(f"Layers: {score.layers_score:.2%}")
            print(f"Platform: {score.platform_score:.2%}")
            print(f"WorkDir: {score.workdir_score:.2%}")
            print(f"Volumes: {score.volumes_score:.2%}")
            
            print("\nDetails:")
            for category, detail in score.details.items():
                print(f"{category}: {detail}")
                
        except Exception as e:
            print(f"Error benchmarking {dockerfile}: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 
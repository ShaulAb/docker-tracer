"""Analyzer for matching Dockerfiles against Docker images."""

import re
import json
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from loguru import logger

from app.config import settings
from app.services.sbom_generator.dockerfile_analyzer import DockerfileAnalysis, DockerInstruction
from .models import Layer, LayerMatch, DockerfileMatch, ImageInfo

class DockerfileMatchAnalyzer:
    """Analyzes how well a Dockerfile matches a Docker image."""

    def analyze_match(self, dockerfile: DockerfileAnalysis, image: ImageInfo) -> DockerfileMatch:
        """Analyze how well a Dockerfile matches a Docker image."""
        try:
            # Match base image
            base_image_score = self._match_base_image(dockerfile.base_image, image.base_image)
            
            # Match layers sequentially
            layer_matches = self._match_layers_sequential(dockerfile.all_instructions, image.layers)
            layer_score = self._compute_layer_score(layer_matches)
            
            # Match metadata (labels, etc)
            metadata_score = self._match_metadata(dockerfile, image)
            
            # Match build context (COPY/ADD commands)
            context_score = self._match_build_context(dockerfile.copy_commands, layer_matches)
            
            # Calculate overall score using configured weights
            overall_score = (
                base_image_score * settings.matching.score_weights.base_image +
                layer_score * settings.matching.score_weights.layer_match +
                metadata_score * settings.matching.score_weights.metadata +
                context_score * settings.matching.score_weights.context
            )
            
            return DockerfileMatch(
                overall_score=overall_score,
                base_image_score=base_image_score,
                layer_score=layer_score,
                metadata_score=metadata_score,
                context_score=context_score,
                matched_layers=layer_matches,
                metadata={
                    'base_image_details': self._get_base_image_details(dockerfile.base_image, image.base_image),
                    'unmatched_layers': self._get_unmatched_layers(layer_matches),
                    'sequence_analysis': self._analyze_sequence_matches(layer_matches),
                    **self._metadata  # Include environment, port, and volume matches
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze Dockerfile match: {str(e)}")
            raise ValueError(f"Match analysis failed: {str(e)}")

    def _match_base_image(self, dockerfile_base: str, image_base: Optional[str]) -> float:
        """Match base images accounting for tags and aliases."""
        if not dockerfile_base or not image_base:
            return 0.0
            
        # Normalize image references
        df_base = self._normalize_image_ref(dockerfile_base)
        img_base = self._normalize_image_ref(image_base)
        
        # Exact match
        if df_base == img_base:
            return 1.0
            
        # Match without tag
        df_name = df_base.split(':')[0]
        img_name = img_base.split(':')[0]
        if df_name == img_name:
            return 0.8
            
        # Check for known aliases
        if self._are_image_aliases(df_base, img_base):
            return 0.9
            
        return 0.0

    def _match_layers_sequential(self, instructions: List[DockerInstruction], layers: List[Layer]) -> List[LayerMatch]:
        """Match Dockerfile instructions to image layers maintaining sequence."""
        matches = []
        for idx, instruction in enumerate(instructions):
            best_match = None
            best_score = settings.matching.layer_matching.partial_match_threshold
            
            for layer in layers:
                score = self._compute_command_similarity(instruction.content, layer.created_by)
                if score >= best_score:
                    best_score = score
                    best_match = LayerMatch(
                        dockerfile_instruction=instruction,
                        layer_info=layer,
                        match_score=score,
                        match_type='exact' if score >= settings.matching.layer_matching.exact_match_threshold else 'partial',
                        details={
                            'sequence_score': 1.0 - (abs(idx - layers.index(layer)) / len(layers)),
                            'command_score': score
                        }
                    )
            
            if best_match:
                matches.append(best_match)
            else:
                # Add unmatched instruction with null layer
                matches.append(LayerMatch(
                    dockerfile_instruction=instruction,
                    layer_info=None,
                    match_score=0.0,
                    match_type='none',
                    details={
                        'sequence_score': 0.0,
                        'command_score': 0.0
                    }
                ))
        
        return matches

    def _compute_command_similarity(self, cmd1: str, cmd2: str) -> float:
        """Compute similarity between two commands."""
        # Normalize commands
        cmd1_norm = self._normalize_command(cmd1)
        cmd2_norm = self._normalize_command(cmd2)
        
        # Get command type weight
        cmd_type = cmd1_norm.split()[0] if cmd1_norm else 'OTHER'
        type_weight = getattr(settings.matching.command_type_weights, cmd_type, 
                            settings.matching.command_type_weights.OTHER)
        
        # Compute token similarity
        tokens1 = set(cmd1_norm.split())
        tokens2 = set(cmd2_norm.split())
        
        if not tokens1 or not tokens2:
            return 0.0
            
        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)
        
        similarity = len(intersection) / len(union)
        return similarity * type_weight

    def _normalize_command(self, cmd: str) -> str:
        """Normalize command for comparison."""
        if not cmd:
            return ""
        # Remove multiple spaces, newlines, tabs
        cmd = re.sub(r'\s+', ' ', cmd)
        # Remove comments
        cmd = re.sub(r'#.*$', '', cmd, flags=re.MULTILINE)
        # Normalize path separators
        cmd = cmd.replace('\\', '/')
        return cmd.strip().upper()

    def _match_metadata(self, dockerfile: DockerfileAnalysis, image: ImageInfo) -> float:
        """Match Dockerfile metadata against image configuration."""
        scores = []
        metadata = {
            'environment_matches': {},
            'port_matches': [],
            'volume_matches': []
        }
        
        # Match labels
        if dockerfile.metadata and image.config.labels:
            label_score = self._match_labels(dockerfile.metadata, image.config.labels)
            scores.append(label_score * settings.matching.label_matching.maintainer)
        
        # Match exposed ports
        if image.config.exposed_ports:
            port_score = self._match_ports(dockerfile.all_instructions, image.config.exposed_ports)
            scores.append(port_score * 0.3)
            # Store matched ports
            for instruction in dockerfile.all_instructions:
                if instruction.type == 'EXPOSE':
                    ports = re.findall(r'\b\d+(?:/(?:tcp|udp))?\b', instruction.content)
                    metadata['port_matches'].extend(ports)
        
        # Match volumes
        if image.config.volumes:
            volume_score = self._match_volumes(dockerfile.all_instructions, image.config.volumes)
            scores.append(volume_score * 0.3)
            # Store matched volumes
            for instruction in dockerfile.all_instructions:
                if instruction.type == 'VOLUME':
                    if instruction.content.strip().startswith('['):
                        try:
                            volumes = json.loads(instruction.content)
                            metadata['volume_matches'].extend(volumes)
                        except json.JSONDecodeError:
                            pass
                    else:
                        volumes = re.findall(r'(?:"([^"]+)"|(\S+))', instruction.content)
                        metadata['volume_matches'].extend(v[0] or v[1] for v in volumes)
        
        # Match environment variables
        for instruction in dockerfile.all_instructions:
            if instruction.type == 'ENV':
                parts = instruction.content.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip().strip('"\'')
                    if key in (image.config.env or {}):
                        metadata['environment_matches'][key] = value
        
        # Store metadata in instance for later use
        self._metadata = metadata
        
        return sum(scores) / len(scores) if scores else 0.0

    def _match_build_context(self, copy_commands: List[DockerInstruction], layer_matches: List[LayerMatch]) -> float:
        """Match build context based on COPY/ADD commands."""
        if not copy_commands:
            return 1.0  # No copy commands to match
            
        total_score = 0.0
        for cmd in copy_commands:
            best_score = 0.0
            for match in layer_matches:
                if match.dockerfile_instruction == cmd:
                    path_score = self._compute_path_similarity(
                        cmd.content,
                        match.layer_info.created_by if match.layer_info else ""
                    )
                    best_score = max(best_score, path_score)
            total_score += best_score
            
        return total_score / len(copy_commands)

    def _compute_path_similarity(self, cmd1: str, cmd2: str) -> float:
        """Compute similarity between paths in COPY/ADD commands."""
        # Extract paths from commands
        paths1 = self._extract_paths(cmd1)
        paths2 = self._extract_paths(cmd2)
        
        if not paths1 or not paths2:
            return 0.0
            
        scores = []
        for p1 in paths1:
            path1 = Path(p1)
            best_path_score = 0.0
            
            for p2 in paths2:
                path2 = Path(p2)
                
                # Exact match
                if path1 == path2:
                    best_path_score = max(best_path_score, 
                                        settings.matching.path_matching.exact_path_score)
                # Parent directory match
                elif path1.parent == path2.parent:
                    best_path_score = max(best_path_score,
                                        settings.matching.path_matching.parent_path_score)
                # Filename match
                elif path1.name == path2.name:
                    best_path_score = max(best_path_score,
                                        settings.matching.path_matching.filename_only_score)
                # Extension match
                elif path1.suffix == path2.suffix:
                    best_path_score = max(best_path_score,
                                        settings.matching.path_matching.extension_match_score)
                    
            scores.append(best_path_score)
            
        return sum(scores) / len(scores) if scores else 0.0

    def _extract_paths(self, cmd: str) -> List[str]:
        """Extract paths from COPY/ADD commands."""
        parts = cmd.split()
        if len(parts) < 3:  # Need at least: COPY/ADD src dest
            return []
        # Remove command name and return all but last part (destination)
        return parts[1:-1]

    def _compute_layer_score(self, matches: List[LayerMatch]) -> float:
        """Compute overall layer matching score."""
        if not matches:
            return 0.0
            
        total_score = 0.0
        for idx, match in enumerate(matches):
            # Weight by both command similarity and sequence position
            sequence_score = 1.0 - (idx / len(matches))  # Earlier matches weighted higher
            total_score += (
                match.match_score * settings.matching.layer_matching.command_weight +
                sequence_score * settings.matching.layer_matching.sequence_weight
            )
            
        return total_score / len(matches)

    def _get_base_image_details(self, dockerfile_base: str, image_base: Optional[str]) -> Dict:
        """Get detailed information about base image matching."""
        return {
            'dockerfile_base': dockerfile_base,
            'image_base': image_base,
            'normalized_dockerfile': self._normalize_image_ref(dockerfile_base),
            'normalized_image': self._normalize_image_ref(image_base) if image_base else None
        }

    def _get_unmatched_layers(self, matches: List[LayerMatch]) -> List[Dict]:
        """Get information about unmatched layers."""
        return [
            {
                'instruction': m.dockerfile_instruction.content,
                'reason': m.details.get('reason', 'Unknown')
            }
            for m in matches
            if m.match_type == 'none'
        ]

    def _analyze_sequence_matches(self, matches: List[LayerMatch]) -> Dict:
        """Analyze how well the sequence of instructions matches."""
        total_matches = len([m for m in matches if m.match_type != 'none'])
        sequence_scores = [
            m.details.get('sequence_score', 0.0)
            for m in matches
            if m.match_type != 'none'
        ]
        
        return {
            'total_matches': total_matches,
            'average_sequence_score': sum(sequence_scores) / len(sequence_scores) if sequence_scores else 0.0,
            'perfect_sequence_matches': len([s for s in sequence_scores if s >= 0.95])
        }

    def _match_labels(self, dockerfile_labels: Dict[str, str], image_labels: Dict[str, str]) -> float:
        """Match Dockerfile labels against image labels."""
        if not dockerfile_labels or not image_labels:
            return 0.0
            
        scores = []
        
        # Check each label with its importance weight
        for label, value in dockerfile_labels.items():
            if label in image_labels:
                weight = settings.matching.label_matching.get(label.lower(), settings.matching.label_matching.other)
                if value.lower() == image_labels[label].lower():
                    scores.append(1.0 * weight)
                else:
                    # Partial match for version labels
                    if 'version' in label.lower():
                        version_score = self._compare_versions(value, image_labels[label])
                        scores.append(version_score * weight)
                    else:
                        # Token similarity for other labels
                        similarity = self._compute_token_similarity(value, image_labels[label])
                        scores.append(similarity * weight)
        
        return sum(scores) / len(scores) if scores else 0.0

    def _match_ports(self, instructions: List[DockerInstruction], image_ports: List[str]) -> float:
        """Match exposed ports from Dockerfile against image configuration."""
        # Extract ports from EXPOSE instructions
        dockerfile_ports = set()
        for instruction in instructions:
            if instruction.type == 'EXPOSE':
                ports = re.findall(r'\b\d+(?:/(?:tcp|udp))?\b', instruction.content)
                dockerfile_ports.update(ports)
        
        if not dockerfile_ports:
            return 1.0 if not image_ports else 0.0
            
        # Normalize ports (add /tcp if no protocol specified)
        dockerfile_ports = {p if '/' in p else f"{p}/tcp" for p in dockerfile_ports}
        image_ports = set(image_ports)
        
        # Calculate matches
        matches = dockerfile_ports & image_ports
        return len(matches) / max(len(dockerfile_ports), len(image_ports))

    def _match_volumes(self, instructions: List[DockerInstruction], image_volumes: List[str]) -> float:
        """Match volume definitions from Dockerfile against image configuration."""
        # Extract volumes from VOLUME instructions
        dockerfile_volumes = set()
        for instruction in instructions:
            if instruction.type == 'VOLUME':
                # Handle both JSON array and space-separated formats
                if instruction.content.strip().startswith('['):
                    try:
                        volumes = json.loads(instruction.content)
                        dockerfile_volumes.update(volumes)
                    except json.JSONDecodeError:
                        pass
                else:
                    volumes = re.findall(r'(?:"([^"]+)"|(\S+))', instruction.content)
                    dockerfile_volumes.update(v[0] or v[1] for v in volumes)
        
        if not dockerfile_volumes:
            return 1.0 if not image_volumes else 0.0
            
        # Normalize paths
        dockerfile_volumes = {str(Path(v)) for v in dockerfile_volumes}
        image_volumes = {str(Path(v)) for v in image_volumes}
        
        # Calculate matches
        matches = dockerfile_volumes & image_volumes
        return len(matches) / max(len(dockerfile_volumes), len(image_volumes))

    def _compare_versions(self, version1: str, version2: str) -> float:
        """Compare version strings and return similarity score."""
        # Extract version numbers
        v1_parts = re.findall(r'\d+', version1)
        v2_parts = re.findall(r'\d+', version2)
        
        if not v1_parts or not v2_parts:
            return 0.0
            
        # Compare each version component
        max_parts = max(len(v1_parts), len(v2_parts))
        matching_parts = 0
        
        for i in range(min(len(v1_parts), len(v2_parts))):
            if v1_parts[i] == v2_parts[i]:
                matching_parts += 1
            else:
                break
        
        return matching_parts / max_parts

    def _normalize_image_ref(self, image_ref: str) -> str:
        """Normalize image reference for comparison."""
        # Remove registry if present
        parts = image_ref.split('/')
        if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0] or parts[0] == 'localhost'):
            image_ref = '/'.join(parts[1:])
        
        # Add latest tag if none specified
        if ':' not in image_ref:
            image_ref += ':latest'
        
        return image_ref.lower()

    def _are_image_aliases(self, img1: str, img2: str) -> bool:
        """Check if two image references are known aliases."""
        # TODO: Implement image alias checking
        return False

    def _compute_token_similarity(self, cmd1: str, cmd2: str) -> float:
        """Compute similarity between command tokens."""
        tokens1 = set(cmd1.split())
        tokens2 = set(cmd2.split())
        
        if not tokens1 or not tokens2:
            return 0.0
            
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)
        
        return intersection / union if union > 0 else 0.0 
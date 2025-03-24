"""Component type definitions for SBOM generation."""

from typing import Dict, List

class Component:
    """Represents a normalized software component in an SBOM."""

    def __init__(
        self,
        name: str,
        version: str,
        type: str,
        purl: str,
        licenses: List[str],
        hashes: Dict[str, str],
        metadata: Dict[str, any]
    ):
        """Initialize a Component.
        
        Args:
            name: Component name
            version: Component version
            type: Component type (e.g., 'npm', 'python', etc.)
            purl: Package URL (purl) for the component
            licenses: List of license identifiers
            hashes: Dictionary of hash algorithms to hash values
            metadata: Additional component metadata
        """
        self.name = name
        self.version = version
        self.type = type
        self.purl = purl
        self.licenses = licenses
        self.hashes = hashes
        self.metadata = metadata

    @classmethod
    def from_dict(cls, data: Dict) -> "Component":
        """Create a Component from a dictionary.
        
        Args:
            data: Dictionary containing component data
            
        Returns:
            Component: New Component instance
        """
        return cls(
            name=data["name"],
            version=data["version"],
            type=data.get("type", "unknown"),
            purl=data["purl"],
            licenses=data.get("licenses", []),
            hashes=data.get("hashes", {}),
            metadata=data.get("metadata", {})
        )

    def to_dict(self) -> Dict:
        """Convert the Component to a dictionary.
        
        Returns:
            Dict: Dictionary representation of the Component
        """
        return {
            "name": self.name,
            "version": self.version,
            "type": self.type,
            "purl": self.purl,
            "licenses": self.licenses,
            "hashes": self.hashes,
            "metadata": self.metadata
        } 
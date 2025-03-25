"""Example script demonstrating how to analyze a Docker image."""

import asyncio
from typing import Dict, Any
from datetime import datetime
from pprint import pprint

from app.services.dockersdk.sdk_client import SDKDockerClient
from app.services.dockersdk.exceptions import DockerImageNotFoundError, DockerError

class DockerImageAnalyzer:
    """Simple analyzer for Docker images."""
    
    def __init__(self):
        """Initialize with Docker client."""
        self.client = SDKDockerClient()

    async def analyze_image(self, image_ref: str) -> Dict[str, Any]:
        """Analyze a Docker image and extract key information.
        
        Args:
            image_ref: Docker image reference (e.g. 'python:3.9')
            
        Returns:
            Dict containing image analysis results
            
        Raises:
            DockerError: If there is an error analyzing the image
        """
        try:
            # Try to get image locally first
            try:
                image = await self.client.get_image(image_ref)
            except DockerImageNotFoundError:
                print(f"Pulling image {image_ref}...")
                image = await self.client.pull_image(image_ref)
            
            # Get detailed image info
            inspection = await self.client.inspect_image(image.id)
            
            # Extract useful information
            config = inspection["Config"]
            return {
                "Id": image.id,
                "RepoTags": image.tags,
                "Created": inspection["Created"],
                "Architecture": inspection["Architecture"],
                "Os": inspection["Os"],
                "Size": inspection["Size"],
                "Layers": len(inspection["RootFS"]["Layers"]),
                "Environment": config.get("Env", []),
                "Entrypoint": config.get("Entrypoint"),
                "Cmd": config.get("Cmd"),
                "WorkingDir": config.get("WorkingDir"),
                "Labels": config.get("Labels", {}),
                "ExposedPorts": list(config.get("ExposedPorts", {}).keys()),
                "Volumes": list(config.get("Volumes", {}).keys()),
                "History": inspection.get("History", [])
            }
        except Exception as e:
            raise DockerError(f"Error analyzing image {image_ref}: {str(e)}") from e

async def main():
    """Run the example."""
    # Create analyzer
    analyzer = DockerImageAnalyzer()
    
    # Analyze a sample image
    image_ref = "python:3.9-slim"  # You can change this to any image
    print(f"\nAnalyzing image: {image_ref}")
    
    try:
        result = await analyzer.analyze_image(image_ref)
        
        # Print results in a readable format
        print("\nImage Analysis Results:")
        print("=" * 50)
        pprint(result)
        
        # Print layer history
        print("\nLayer History:")
        print("=" * 50)
        for idx, layer in enumerate(result["History"], 1):
            created_by = layer.get("created_by", "unknown")
            if created_by.startswith("/bin/sh -c #(nop) "):
                created_by = created_by[19:]
            print(f"{idx}. {created_by}")
            
    except Exception as e:
        print(f"Error analyzing image: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 
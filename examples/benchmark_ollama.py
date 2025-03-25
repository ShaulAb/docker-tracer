"""Example script to benchmark Ollama Dockerfile against its image."""

import asyncio
import json
from pathlib import Path
from loguru import logger

from app.services.dockersdk.match_benchmark import BenchmarkRunner
from app.services.sbom_generator.container_analyzer import DockerImageInspector

async def main():
    """Run the benchmark."""
    # Create a sample Dockerfile with Ollama content
    dockerfile_content = """FROM ubuntu:20.04

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH=/usr/local/nvidia/lib:/usr/local/nvidia/lib64
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility
ENV NVIDIA_VISIBLE_DEVICES=all
ENV OLLAMA_HOST=0.0.0.0:11434

EXPOSE 11434

ENTRYPOINT ["/bin/ollama"]
CMD ["serve"]
"""
    
    dockerfile_path = Path("Dockerfile.ollama")
    dockerfile_path.write_text(dockerfile_content)
    
    try:
        # First get raw image data for debugging
        inspector = DockerImageInspector()
        image_data = await inspector.inspect_image("ollama/ollama:latest")
        logger.info("Raw image inspection data:")
        logger.info(json.dumps(image_data, indent=2))
        
        # Log specific fields for debugging
        logger.info("ExposedPorts:")
        logger.info(json.dumps(image_data.get("Config", {}).get("ExposedPorts", {}), indent=2))
        
        # Run the benchmark
        benchmark = BenchmarkRunner()
        score = await benchmark.run_benchmark(str(dockerfile_path), "ollama/ollama:latest")
        
        print("\nBenchmarking Ollama Dockerfile against ollama/ollama:latest")
        print("=" * 60)
        
        print(f"\nOverall Match Score: {score.overall_score:.2%}\n")
        print("Detailed Scores:")
        print(f"Environment Variables: {score.environment_score:.2%}")
        print(f"Exposed Ports: {score.ports_score:.2%}")
        print(f"Commands (CMD/ENTRYPOINT): {score.commands_score:.2%}")
        print(f"Layer History: {score.layers_score:.2%}")
        print(f"Platform/Architecture: {score.platform_score:.2%}")
        print(f"Working Directory: {score.workdir_score:.2%}")
        print(f"Volumes: {score.volumes_score:.2%}")
        
        print("\nMatching Details:\n")
        for category, details in score.details.items():
            print(f"{category}:")
            print("-" * 40)
            print(f"{details}\n")
            
    except Exception as e:
        print(f"Error running benchmark: {e}")
    finally:
        # Cleanup
        dockerfile_path.unlink()

if __name__ == "__main__":
    asyncio.run(main()) 
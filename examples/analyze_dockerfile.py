"""Example script demonstrating how to analyze a Dockerfile."""

import asyncio
from pathlib import Path
from pprint import pprint

from app.services.sbom_generator.dockerfile_analyzer import DockerfileAnalyzer
from app.services.dockersdk.models import DockerfileInstruction, InstructionType

async def analyze_dockerfile(dockerfile_path: str) -> dict:
    """Analyze a Dockerfile and extract key information.
    
    Args:
        dockerfile_path: Path to the Dockerfile
        
    Returns:
        Dict containing analysis results
    """
    analyzer = DockerfileAnalyzer()
    instructions = await analyzer.parse_dockerfile(dockerfile_path)
    
    # Extract key information
    base_image = None
    env_vars = {}
    exposed_ports = []
    volumes = []
    labels = {}
    workdir = None
    cmd = None
    entrypoint = None
    
    for inst in instructions:
        if inst.type == InstructionType.FROM and not base_image:
            base_image = inst.args[0]
        elif inst.type == InstructionType.ENV:
            if len(inst.args) == 2:
                env_vars[inst.args[0]] = inst.args[1]
        elif inst.type == InstructionType.EXPOSE:
            exposed_ports.extend(inst.args)
        elif inst.type == InstructionType.VOLUME:
            volumes.extend(inst.args)
        elif inst.type == InstructionType.LABEL:
            for i in range(0, len(inst.args), 2):
                if i + 1 < len(inst.args):
                    labels[inst.args[i]] = inst.args[i + 1]
        elif inst.type == InstructionType.WORKDIR:
            workdir = inst.args[0]
        elif inst.type == InstructionType.CMD:
            cmd = inst.args
        elif inst.type == InstructionType.ENTRYPOINT:
            entrypoint = inst.args
    
    return {
        "base_image": base_image,
        "environment": env_vars,
        "exposed_ports": exposed_ports,
        "volumes": volumes,
        "labels": labels,
        "working_dir": workdir,
        "cmd": cmd,
        "entrypoint": entrypoint,
        "instruction_count": len(instructions),
        "instructions": [
            {
                "type": inst.type.value,
                "value": inst.value,
                "line": inst.line_number,
                "args": inst.args
            }
            for inst in instructions
        ]
    }

async def main():
    """Run the example."""
    # Create a sample Dockerfile
    dockerfile = """FROM python:3.9-slim
ENV APP_HOME=/app
WORKDIR $APP_HOME
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]
"""
    
    # Write sample Dockerfile
    dockerfile_path = Path("Dockerfile.example")
    dockerfile_path.write_text(dockerfile)
    
    try:
        print("\nAnalyzing Dockerfile:")
        print("=" * 50)
        print(dockerfile)
        
        # Analyze Dockerfile
        result = await analyze_dockerfile(str(dockerfile_path))
        
        print("\nAnalysis Results:")
        print("=" * 50)
        pprint(result)
        
    except Exception as e:
        print(f"Error analyzing Dockerfile: {e}")
    finally:
        # Cleanup
        dockerfile_path.unlink()

if __name__ == "__main__":
    asyncio.run(main()) 
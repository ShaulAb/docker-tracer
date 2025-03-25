"""Test script for Docker command parsing and normalization.

This script tests the DockerCommandNormalizer with various command formats
commonly found in Dockerfiles and Docker image inspections.
"""
from loguru import logger
from app.services.dockersdk.command_utils import DockerCommandNormalizer

# Configure loguru for detailed output
logger.remove()  # Remove default handler
logger.add(sink=lambda msg: print(msg), level="DEBUG")

def test_command(cmd, description):
    """Test a single command and print results."""
    logger.info(f"\n=== Testing {description} ===")
    logger.info(f"Input command: {repr(cmd)}")
    try:
        normalized = DockerCommandNormalizer.normalize(cmd)
        logger.info(f"Normalized result:")
        logger.info(f"  Executable: {repr(normalized.executable)}")
        logger.info(f"  Args: {repr(normalized.args)}")
        logger.info(f"  Is shell form: {normalized.is_shell_form}")
        return normalized
    except Exception as e:
        logger.error(f"Error normalizing command: {e}")
        return None

def main():
    """Run command parsing tests."""
    # Test cases from Dockerfile
    test_cases = [
        # String form (shell format)
        ("serve", "Simple shell command"),
        ("/bin/ollama serve", "Shell command with path"),
        
        # String form (exec format as string)
        ('["/bin/ollama", "serve"]', "Exec format as string"),
        ('["ollama", "serve"]', "Simple exec format as string"),
        
        # List form (exec format)
        (["/bin/ollama", "serve"], "Exec format as list"),
        (["ollama", "serve"], "Simple exec format as list"),
        
        # Edge cases
        (None, "None command"),
        ("", "Empty string"),
        ([], "Empty list"),
        ("[invalid json]", "Invalid JSON string"),
        
        # Real-world examples
        ('["/bin/sh", "-c", "echo hello"]', "Shell command in exec format"),
        ("/bin/sh -c 'echo hello'", "Shell command with quotes"),
        ('["python", "-m", "pip", "install", "package"]', "pip install command"),
    ]
    
    # Run tests and store results for comparison
    results = []
    for cmd, desc in test_cases:
        result = test_command(cmd, desc)
        if result:
            results.append((desc, result))
    
    # Test equality comparisons
    logger.info("\n=== Testing Command Equality ===")
    for i, (desc1, cmd1) in enumerate(results):
        for desc2, cmd2 in results[i+1:]:
            equal = DockerCommandNormalizer.commands_equal(cmd1, cmd2)
            if equal:
                logger.info(f"Match found: '{desc1}' equals '{desc2}'")
                logger.info(f"  {cmd1} == {cmd2}")

if __name__ == "__main__":
    main() 
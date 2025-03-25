"""Custom exceptions for Docker service operations."""


class DockerServiceError(Exception):
    """Base class for Docker service errors."""


class ImageNotFoundError(DockerServiceError):
    """Error raised when a Docker image is not found."""

    def __init__(self, image_name: str) -> None:
        """Initialize the error.
        
        Args:
            image_name: Name of the image that was not found
        """
        self.image_name = image_name
        super().__init__(f"Image '{image_name}' not found")


class InspectionError(DockerServiceError):
    """Error raised when image inspection fails."""

    def __init__(self, image_name: str, reason: str) -> None:
        """Initialize the error.
        
        Args:
            image_name: Name of the image that failed inspection
            reason: Reason for the failure
        """
        self.image_name = image_name
        self.reason = reason
        super().__init__(f"Failed to inspect image '{image_name}': {reason}")


class LayerAnalysisError(DockerServiceError):
    """Error raised when layer analysis fails."""

    def __init__(self, image_name: str, reason: str) -> None:
        """Initialize the error.
        
        Args:
            image_name: Name of the image that failed analysis
            reason: Reason for the failure
        """
        self.image_name = image_name
        self.reason = reason
        super().__init__(f"Failed to analyze layers for image '{image_name}': {reason}")


class ConfigurationError(DockerServiceError):
    """Error raised when there is a configuration issue."""

    def __init__(self, message: str) -> None:
        """Initialize the error.
        
        Args:
            message: Error message
        """
        super().__init__(f"Docker configuration error: {message}")


class PackageAnalysisError(DockerServiceError):
    """Error raised when package analysis fails."""

    def __init__(self, image_name: str, reason: str) -> None:
        """Initialize the error.
        
        Args:
            image_name: Name of the image that failed analysis
            reason: Reason for the failure
        """
        self.image_name = image_name
        self.reason = reason
        super().__init__(f"Failed to analyze packages in image '{image_name}': {reason}") 
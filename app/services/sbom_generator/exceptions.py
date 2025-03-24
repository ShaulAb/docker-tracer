"""Exceptions for SBOM generation."""

class SBOMGenerationError(Exception):
    """Base class for SBOM generation errors."""
    pass

class InvalidImageError(SBOMGenerationError):
    """Raised when container image is invalid or cannot be accessed."""
    pass

class AnalysisError(SBOMGenerationError):
    """Raised when SBOM analysis fails."""
    pass

class NormalizationError(SBOMGenerationError):
    """Raised when SBOM data normalization fails."""
    pass 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.endpoints import sbom
from app.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Match Docker images to their source code repositories using SBOM analysis",
    version=settings.VERSION,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,  # Using the new property
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(sbom.router, prefix=settings.API_V1_STR, tags=["sbom"])

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": "Match Docker images to their source code repositories using SBOM analysis",
    } 
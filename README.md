# Docker Source Matcher

A tool for matching Docker images to their source code repositories using SBOM (Software Bill of Materials) analysis.

## Features

- Generate and analyze SBOMs from Docker images
- Match Docker images to source code repositories
- Advanced matching algorithm with weighted scoring
- Interactive visualization of match analysis
- Layer-by-layer comparison
- Support for GitHub repositories and local Dockerfiles
- RESTful API for integration
- Efficient storage and caching of results

## Visualization Features

- Interactive radar chart for match score analysis
- Real-time score updates and visualization
- Comprehensive match breakdown display
- Support for multiple visualization types
- Detailed layer-by-layer analysis
- Intuitive and responsive user interface

## Prerequisites

- Python 3.9 or higher
- Docker and Docker Compose
- PostgreSQL 15
- UV package manager

## Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd docker-source-matcher
   ```

2. Set up the Python environment:
   ```bash
   uv venv
   source .venv/bin/activate  # On Unix-like systems
   # or
   .venv\Scripts\activate  # On Windows
   ```

3. Install dependencies:
   ```bash
   uv pip install -e ".[dev]"
   ```

4. Start the development database:
   ```bash
   docker-compose up -d
   ```

5. Create a `.env` file:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

6. Run the development server:
   ```bash
   uvicorn app.main:app --reload
   ```

The API will be available at `http://localhost:8000`

## API Documentation

Once the server is running, you can access:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Testing

Run tests with pytest:
```bash
pytest
```

## License

[Your chosen license] 
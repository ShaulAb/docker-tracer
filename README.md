# Docker (*Fuzzy*) Tracing Tool

A basic tool to provide matching score betwee a Docker image and a Dockerfile / git repository.

<br>

## Overview

This tool implements a score (probablity) that a Docker image is the outcome of a Dockerfile / git repo.  
Components:

1. **Sequential Layer Analysis (40%)**
   - Matches Dockerfile instructions to image layers
   - Considers command similarity and layer ordering
   - Handles BuildKit optimizations and shell variations
   - Parsing of RUN, COPY, and ADD instructions

2. **Base Image Verification (20%)**
   - Exact matching including tags
   - Registry-agnostic comparison
   - Platform/architecture validation
   - Support for known image aliases

3. **Metadata Correlation (20%)**
   - Label matching with weighted importance
   - Environment variable verification
   - Port and volume definition validation
   - Working directory analysis

4. **Build Context Analysis (20%)**
   - Path pattern matching for COPY/ADD instructions
   - File and directory structure validation
   - Extension and content type verification
   - Multi-stage build awareness

<br>

## Match Quality Scoring

Score interpretation:

- **0.9 - 1.0**: Excellent match (Very high confidence)
- **0.8 - 0.9**: Good match (High confidence)
- **0.6 - 0.8**: Fair match (Possible derivative)
- **< 0.6**: Poor match (Likely unrelated)

<br>

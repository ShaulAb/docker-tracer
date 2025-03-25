"""GitHub client service for repository operations."""

import os
from typing import Dict, List, Optional
from github import Github, Repository
from loguru import logger

from app.config import settings

class GitHubClient:
    """Client for interacting with GitHub repositories."""

    def __init__(self, token: Optional[str] = None):
        """Initialize GitHub client.
        
        Args:
            token: Optional GitHub token for authenticated requests
        """
        self.token = token or settings.GITHUB_TOKEN or os.getenv("GITHUB_TOKEN")
        self.client = Github(self.token) if self.token else Github()
        logger.debug("Initialized GitHub client")

    def get_repository(self, repo_url: str) -> Repository.Repository:
        """Get repository information from URL.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Repository: GitHub repository object
            
        Raises:
            ValueError: If URL is invalid or repository not found
        """
        try:
            # Extract owner and repo name from URL
            # Handle both HTTPS and SSH URLs
            if "github.com/" in repo_url:
                parts = repo_url.split("github.com/")[-1].rstrip("/").split("/")
            else:
                raise ValueError(f"Invalid GitHub URL: {repo_url}")

            if len(parts) < 2:
                raise ValueError(f"Invalid repository URL format: {repo_url}")

            owner, repo = parts[0], parts[1]
            return self.client.get_repo(f"{owner}/{repo}")

        except Exception as e:
            logger.error(f"Failed to get repository {repo_url}: {str(e)}")
            raise ValueError(f"Failed to get repository: {str(e)}")

    def get_dockerfile_content(self, repo: Repository.Repository, path: str = "Dockerfile") -> str:
        """Get Dockerfile content from repository.
        
        Args:
            repo: GitHub repository object
            path: Path to Dockerfile, defaults to root Dockerfile
            
        Returns:
            str: Dockerfile content
            
        Raises:
            ValueError: If Dockerfile not found
        """
        try:
            content = repo.get_contents(path)
            if isinstance(content, list):
                raise ValueError(f"Path {path} is a directory")
            return content.decoded_content.decode('utf-8')

        except Exception as e:
            logger.error(f"Failed to get Dockerfile from {repo.full_name}: {str(e)}")
            raise ValueError(f"Failed to get Dockerfile: {str(e)}")

    def get_repository_files(self, repo: Repository.Repository, path: str = "") -> List[Dict[str, str]]:
        """Get list of files in repository directory.
        
        Args:
            repo: GitHub repository object
            path: Optional path within repository
            
        Returns:
            List[Dict]: List of file information
        """
        try:
            contents = repo.get_contents(path)
            files = []
            
            for content in contents:
                files.append({
                    "name": content.name,
                    "path": content.path,
                    "type": "dir" if content.type == "dir" else "file",
                    "size": content.size,
                })
            
            return files

        except Exception as e:
            logger.error(f"Failed to list files in {repo.full_name}: {str(e)}")
            return []

    def find_dockerfiles(self, repo: Repository.Repository) -> List[str]:
        """Find all Dockerfiles in repository.
        
        Args:
            repo: GitHub repository object
            
        Returns:
            List[str]: List of Dockerfile paths
        """
        try:
            # Search for files named Dockerfile or *.dockerfile
            dockerfiles = []
            
            # Search in root first
            try:
                content = repo.get_contents("Dockerfile")
                if not isinstance(content, list):
                    dockerfiles.append("Dockerfile")
            except:
                pass

            # Search entire repository
            contents = repo.get_contents("")
            dirs = [c for c in contents if c.type == "dir"]

            while dirs:
                dir_content = dirs.pop(0)
                try:
                    for content in repo.get_contents(dir_content.path):
                        if content.type == "dir":
                            dirs.append(content)
                        elif content.name.lower() == "dockerfile" or content.name.lower().endswith(".dockerfile"):
                            dockerfiles.append(content.path)
                except:
                    continue

            return dockerfiles

        except Exception as e:
            logger.error(f"Failed to find Dockerfiles in {repo.full_name}: {str(e)}")
            return [] 
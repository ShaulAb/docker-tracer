"""Gradio interface for analyzing Docker images and Dockerfiles."""

import asyncio
from typing import Tuple, Dict, Optional, Union
from urllib.parse import urlparse
from pathlib import Path
from loguru import logger
import sys
import json
import os
from dotenv import load_dotenv
import gradio as gr
import pandas as pd
import plotly.graph_objects as go
from github import Github
from github.GithubException import GithubException

load_dotenv(".env")

# append the parent directory to the sys path
sys.path.append("..")
from app.services.dockersdk.match_benchmark import BenchmarkRunner
from app.services.dockersdk.sdk_client import SDKDockerClient
from app.services.sbom_generator.dockerfile_analyzer import DockerfileAnalyzer

# Initialize GitHub client
github_token = os.getenv('GITHUB_TOKEN')
if not github_token:
    logger.warning("GITHUB_TOKEN not set. GitHub functionality will be limited.")
github_client = Github(github_token) if github_token else None

def extract_repo_info(repo_url: str) -> Tuple[str, str]:
    """Extract owner and repo name from GitHub URL."""
    parsed = urlparse(repo_url)
    if not parsed.netloc or 'github.com' not in parsed.netloc:
        raise ValueError("Invalid GitHub repository URL")
        
    parts = parsed.path.strip('/').split('/')
    if len(parts) < 2:
        raise ValueError("Invalid GitHub repository URL format")
        
    return parts[0], parts[1]

async def fetch_dockerfile(repo_url: str) -> str:
    """Fetch Dockerfile from GitHub repository."""
    if not github_client:
        raise ValueError("GitHub token not set. Please set GITHUB_TOKEN environment variable.")
        
    try:
        owner, repo = extract_repo_info(repo_url)
        
        # Get repository
        repo_obj = github_client.get_repo(f"{owner}/{repo}")
        
        # Common Dockerfile locations
        dockerfile_paths = [
            'Dockerfile',
            '.docker/Dockerfile',
            'docker/Dockerfile',
            '.dockerfile/Dockerfile',
            'build/Dockerfile'
        ]
        
        for path in dockerfile_paths:
            try:
                content = repo_obj.get_contents(path)
                if content:
                    return content.decoded_content.decode('utf-8')
            except GithubException as e:
                logger.debug(f"Failed to fetch Dockerfile from {path}: {str(e)}")
                continue
        
        raise ValueError(f"No Dockerfile found in repository {repo_url}")
    except GithubException as e:
        if e.status == 404:
            raise ValueError(f"Repository not found: {repo_url}")
        elif e.status == 403:
            raise ValueError("GitHub API rate limit exceeded or authentication required. Please set GITHUB_TOKEN environment variable.")
        else:
            raise ValueError(f"GitHub API error: {str(e)}")

def create_score_visualization(match_result) -> go.Figure:
    """Create a radar chart visualization of match scores."""
    import plotly.graph_objects as go
    
    categories = [
        'Overall',
        'Environment',
        'Ports',
        'Commands',
        'Layers',
        'Platform',
        'Working Dir',
        'Volumes'
    ]
    scores = [
        match_result.overall_score,
        match_result.environment_score,
        match_result.ports_score,
        match_result.commands_score,
        match_result.layers_score,
        match_result.platform_score,
        match_result.workdir_score,
        match_result.volumes_score
    ]
    
    # Convert scores to percentages and close the polygon
    scores_pct = [s * 100 for s in scores]
    categories_closed = categories + [categories[0]]
    scores_closed = scores_pct + [scores_pct[0]]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=scores_closed,
        theta=categories_closed,
        fill='toself',
        name='Match Score'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                range=[0, 100],
                ticksuffix='%'
            )
        ),
        title='Match Score Analysis',
        showlegend=False
    )
    
    return fig

def create_layer_visualization(matches_df: pd.DataFrame) -> go.Figure:
    """Create a visualization of layer matches."""
    if matches_df.empty:
        # Create empty plot with message
        fig = go.Figure()
        fig.add_annotation(
            text="No layer matches to display",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False
        )
        return fig
        
    try:
        # Convert scores to float, replacing any invalid values with 0.0
        match_scores = pd.to_numeric(matches_df['Match Score'], errors='coerce').fillna(0.0)
        sequence_scores = pd.to_numeric(matches_df['Sequence Score'], errors='coerce').fillna(0.0)
        command_scores = pd.to_numeric(matches_df['Command Score'], errors='coerce').fillna(0.0)
        
        fig = go.Figure()
        
        # Add trace for match scores
        fig.add_trace(go.Scatter(
            x=range(len(matches_df)),
            y=match_scores,
            mode='lines+markers',
            name='Overall Match',
            hovertext=[
                f"Instruction: {instr}<br>"
                f"Layer: {layer}<br>"
                f"Match Type: {mtype}"
                for instr, layer, mtype in zip(
                    matches_df['Dockerfile Instruction'],
                    matches_df['Image Layer'],
                    matches_df['Match Type']
                )
            ]
        ))
        
        # Add trace for sequence scores
        fig.add_trace(go.Scatter(
            x=range(len(matches_df)),
            y=sequence_scores,
            mode='lines+markers',
            name='Sequence Match',
            visible='legendonly'
        ))
        
        # Add trace for command scores
        fig.add_trace(go.Scatter(
            x=range(len(matches_df)),
            y=command_scores,
            mode='lines+markers',
            name='Command Match',
            visible='legendonly'
        ))
        
        fig.update_layout(
            title="Layer Match Analysis",
            xaxis_title="Layer Index",
            yaxis_title="Match Score",
            yaxis=dict(range=[0, 1]),
            showlegend=True,
            hovermode='closest'
        )
        return fig
    except Exception as e:
        logger.error(f"Error creating layer visualization: {e}")
        # Return empty plot with error message
        fig = go.Figure()
        fig.add_annotation(
            text=f"Error creating visualization: {str(e)}",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False
        )
        return fig

async def analyze_match(
    repo_url: Optional[str],
    dockerfile_upload: Optional[Union[str, Path]],
    docker_image: str,
    progress=gr.Progress()
) -> Tuple[str, float, go.Figure, Dict]:
    """Analyze Dockerfile match with Docker image."""
    try:
        progress(0, desc="Initializing analysis...")
        
        # Validate inputs
        if not docker_image:
            raise ValueError("Please provide a Docker image reference")
        if not repo_url and not dockerfile_upload:
            raise ValueError("Please provide either a GitHub repository URL or upload a Dockerfile")
        
        try:
            # Get Dockerfile content
            progress(0.2, desc="Getting Dockerfile...")
            if dockerfile_upload:
                dockerfile_path = dockerfile_upload
            elif repo_url:
                # Save Dockerfile content to temporary file
                dockerfile_content = await fetch_dockerfile(repo_url)
                dockerfile_path = Path("temp_dockerfile")
                dockerfile_path.write_text(dockerfile_content)
            
            # Run benchmark analysis
            progress(0.6, desc="Analyzing match...")
            benchmark = BenchmarkRunner()
            match_result = await benchmark.run_benchmark(dockerfile_path, docker_image)
            
            # Create visualizations
            progress(0.8, desc="Creating visualizations...")
            score_viz = create_score_visualization(match_result)
            
            # Format status message
            status = f"Analysis complete!\n\n"
            status += f"Overall Match Score: {match_result.overall_score:.2%}\n\n"
            status += "Detailed Scores:\n"
            status += f"Environment Variables: {match_result.environment_score:.2%}\n"
            status += f"Exposed Ports: {match_result.ports_score:.2%}\n"
            status += f"Commands (CMD/ENTRYPOINT): {match_result.commands_score:.2%}\n"
            status += f"Layer History: {match_result.layers_score:.2%}\n"
            status += f"Platform/Architecture: {match_result.platform_score:.2%}\n"
            status += f"Working Directory: {match_result.workdir_score:.2%}\n"
            status += f"Volumes: {match_result.volumes_score:.2%}\n"
            
            # Add detailed matches
            status += "\nDetailed Matches:\n"
            for category, details in match_result.details.items():
                status += f"\n{category}:\n"
                status += "-" * 40 + "\n"
                status += f"{details}\n"
            
            progress(1.0, desc="Done!")
            return (
                status,
                match_result.overall_score,
                score_viz,
                match_result.details
            )
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return f"Analysis failed: {str(e)}", 0.0, None, {}
        finally:
            # Cleanup temporary file if created
            if repo_url and 'dockerfile_path' in locals():
                try:
                    Path(dockerfile_path).unlink()
                except:
                    pass
            
    except ValueError as e:
        return str(e), 0.0, None, {}
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return f"Analysis failed: {str(e)}", 0.0, None, {}

def create_interface():
    """Create Gradio interface."""
    with gr.Blocks(
        title="Docker Image Analyzer",
        theme=gr.themes.Default(),  # Use default light theme
        css="""
            .gradio-container {
                max-width: 1200px !important;
                margin-left: auto !important;
                margin-right: auto !important;
            }
            .contain {
                max-width: 1100px !important;
                margin-left: auto !important;
                margin-right: auto !important;
            }
            .score-plot {
                background-color: white !important;
                border-radius: 8px !important;
                box-shadow: 0 1px 3px rgba(0,0,0,0.12) !important;
                padding: 16px !important;
            }
        """
    ) as interface:
        with gr.Column(elem_classes="contain"):
            gr.Markdown(
                """
                # 🐳 Docker Image Analyzer
                Analyze how well a Dockerfile matches a Docker image by comparing layer instructions, environment variables, ports, volumes, and build context.
                """
            )
            
            # Input Section - More compact layout
            with gr.Row():
                # Left column - Repository/Dockerfile inputs
                with gr.Column(scale=2):
                    with gr.Group():
                        repo_url = gr.Textbox(
                            label="GitHub Repository URL",
                            placeholder="https://github.com/owner/repo",
                            interactive=True,
                            container=False
                        )
                        gr.Markdown("**OR**", container=False)
                        dockerfile_upload = gr.File(
                            label="Upload Dockerfile",
                            file_types=[".dockerfile", ".txt", ""],
                            type="filepath",
                            container=False
                        )
                
                # Right column - Docker image input and analyze button
                with gr.Column(scale=1):
                    docker_image = gr.Textbox(
                        label="Docker Image",
                        placeholder="image:tag",
                        interactive=True,
                        container=False
                    )
                    analyze_btn = gr.Button("🔍 Analyze Match", variant="primary", size="lg")
            
            # Results Section - Two column layout
            with gr.Row(equal_height=True):
                # Left column - Analysis results and score
                with gr.Column(scale=1):
                    match_score = gr.Number(
                        label="Overall Match Score",
                        interactive=False,
                        value=0.0,
                        container=True
                    )
                    status = gr.Textbox(
                        label="Analysis Results",
                        interactive=False,
                        lines=8,
                        container=True,
                        show_copy_button=True
                    )
                
                # Right column - Score visualization
                with gr.Column(scale=1):
                    score_plot = gr.Plot(
                        label="Score Analysis",
                        container=True,
                        elem_classes="score-plot",
                        show_label=True
                    )
            
            # Detailed Results - Collapsible section
            with gr.Accordion("📋 Detailed Match Information", open=False):
                metadata = gr.JSON()
            
            analyze_btn.click(
                fn=analyze_match,
                inputs=[repo_url, dockerfile_upload, docker_image],
                outputs=[status, match_score, score_plot, metadata],
                api_name="analyze"
            )
    
    return interface

if __name__ == "__main__":
    interface = create_interface()
    interface.launch(share=True) 
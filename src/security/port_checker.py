"""
Port Checker Module for Fulcrum

This module provides functionality to check if specific ports are open/closed
across GCP projects by examining firewall rules.
"""
import json
import subprocess
from typing import List, Dict, Any, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import concurrent.futures

console = Console()

class PortChecker:
    """Checks port status across GCP projects by examining firewall rules."""
    
    def __init__(self, projects: List[str], port: int):
        self.projects = projects
        self.port = port
        self.results: List[Dict[str, Any]] = []

    def check_project(self, project_id: str) -> Dict[str, Any]:
        """Check if the specified port is open in the given project.
        
        Args:
            project_id: The GCP project ID to check
            
        Returns:
            Dict containing project ID and port status information
        """
        try:
            # Get all firewall rules that allow the specified port
            cmd = [
                'gcloud', 'compute', 'firewall-rules', 'list',
                f'--project={project_id}',
                '--format=json',
                '--filter=ALLOW AND (direction=INGRESS OR direction=INGRESS_ENABLED)'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            firewall_rules = json.loads(result.stdout)
            
            open_rules = []
            
            for rule in firewall_rules:
                if not rule.get('allowed', []):
                    continue
                    
                for allowed in rule['allowed']:
                    # Check if the rule allows any port or the specific port we're looking for
                    if 'ports' in allowed:
                        ports = allowed['ports']
                        for port_range in ports:
                            # Handle port ranges (e.g., "1000-2000")
                            if '-' in port_range:
                                start, end = map(int, port_range.split('-'))
                                if start <= self.port <= end:
                                    open_rules.append({
                                        'name': rule['name'],
                                        'network': rule.get('network', '').split('/')[-1],
                                        'source_ranges': rule.get('sourceRanges', []),
                                        'target_tags': rule.get('targetTags', []),
                                        'priority': rule.get('priority', '')
                                    })
                                    break
                            # Handle single port
                            elif port_range == str(self.port):
                                open_rules.append({
                                    'name': rule['name'],
                                    'network': rule.get('network', '').split('/')[-1],
                                    'source_ranges': rule.get('sourceRanges', []),
                                    'target_tags': rule.get('targetTags', []),
                                    'priority': rule.get('priority', '')
                                })
                                break
            
            return {
                'project_id': project_id,
                'is_open': len(open_rules) > 0,
                'open_rules': open_rules
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'project_id': project_id,
                'error': f"Error checking project: {e.stderr}",
                'is_open': False,
                'open_rules': []
            }
        except Exception as e:
            return {
                'project_id': project_id,
                'error': f"Unexpected error: {str(e)}",
                'is_open': False,
                'open_rules': []
            }
    
    def run_checks(self, max_workers: int = 5) -> None:
        """Run port checks across all projects in parallel.
        
        Args:
            max_workers: Maximum number of parallel checks to run
        """
        with Progress() as progress:
            task = progress.add_task(
                f"[cyan]Checking port {self.port} across {len(self.projects)} projects...",
                total=len(self.projects)
            )
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_project = {
                    executor.submit(self.check_project, project): project
                    for project in self.projects
                }
                
                for future in concurrent.futures.as_completed(future_to_project):
                    project = future_to_project[future]
                    try:
                        result = future.result()
                        self.results.append(result)
                    except Exception as e:
                        self.results.append({
                            'project_id': project,
                            'error': str(e),
                            'is_open': False,
                            'open_rules': []
                        })
                    progress.update(task, advance=1)
    
    def export_json(self, filename: str) -> None:
        """Export results to a JSON file."""
        import json
        from datetime import datetime, timezone
        
        report_data = {
            "port": self.port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_projects": len(self.results),
                "projects_with_open_port": sum(1 for r in self.results if r.get('is_open', False)),
                "projects_with_closed_port": sum(1 for r in self.results if not r.get('is_open', False)),
                "projects_with_errors": sum(1 for r in self.results if 'error' in r)
            },
            "projects": self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        console.print(f"[green]Report exported to {filename}[/]")
    
    def print_results(self) -> None:
        """Print the results in a formatted table."""
        table = Table(title=f"Port {self.port} Status Across Projects")
        table.add_column("Project ID", style="cyan", no_wrap=True)
        table.add_column("Status", style="magenta")
        table.add_column("Open Rules", style="yellow")
        table.add_column("Source Ranges", style="green")
        
        for result in sorted(self.results, key=lambda x: x['project_id']):
            if 'error' in result:
                table.add_row(
                    result['project_id'],
                    "[red]Error",
                    "N/A",
                    result.get('error', 'Unknown error')
                )
            else:
                status = "[red]OPEN" if result['is_open'] else "[green]CLOSED"
                rule_count = len(result['open_rules'])
                rules = "\n".join([
                    f"{i+1}. {rule['name']} (Network: {rule['network']}, Priority: {rule['priority']})"
                    for i, rule in enumerate(result['open_rules'])
                ]) if rule_count > 0 else "None"
                
                # Get unique source ranges from all open rules
                source_ranges = set()
                for rule in result['open_rules']:
                    source_ranges.update(rule.get('source_ranges', []))
                source_ranges_str = ", ".join(sorted(source_ranges)) if source_ranges else "N/A"
                
                table.add_row(
                    result['project_id'],
                    status,
                    f"{rule_count} rule{'s' if rule_count != 1 else ''}",
                    source_ranges_str
                )
                
                # Add rule details if any
                if rule_count > 0:
                    for i, rule in enumerate(result['open_rules']):
                        table.add_row(
                            "",  # Empty project ID for indentation
                            f"  Rule {i+1}:",
                            rule['name'],
                            f"Network: {rule['network']}, Priority: {rule['priority']}"
                        )
                        if rule.get('target_tags'):
                            table.add_row(
                                "", "",
                                "Target Tags:",
                                ", ".join(rule['target_tags'])
                            )
        
        console.print(table)

def check_port(projects: List[str], port: int, max_workers: int = 5, export_format: Optional[str] = None) -> None:
    """Check if a specific port is open across multiple GCP projects.
    
    Args:
        projects: List of GCP project IDs to check
        port: Port number to check
        max_workers: Maximum number of parallel checks to run
        export_format: Optional export format ('json')
    """
    checker = PortChecker(projects, port)
    checker.run_checks(max_workers)
    
    if export_format == 'json':
        filename = f"port_{port}_report.json"
        checker.export_json(filename)
    else:
        checker.print_results()

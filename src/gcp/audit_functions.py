import subprocess
import json
import sys
from typing import List, Dict, Any

def run_gcloud(args: List[str]) -> Any:
    try:
        cmd = ["gcloud"] + args + ["--format=json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running command {' '.join(cmd)}: {e.stderr}", file=sys.stderr)
        return None

def list_functions(project_id: str):
    print(f"Checking functions in {project_id}...")
    functions = run_gcloud(["functions", "list", "--project", project_id])
    if not functions:
        print(f"No functions found or error accessing {project_id}")
        return

    for func in functions:
        name = func.get("name")
        runtime = func.get("runtime")
        status = func.get("status")
        # Check generation (environment)
        # 1st gen usually implies 'CLOUD_FUNCTIONS_v1' or unspecified environment?
        # 'environment' field might be 'GEN_1' or 'GEN_2'
        environment = func.get("environment", "GEN_1") 
        
        print(f"  - Name: {name}")
        print(f"    Runtime: {runtime}")
        print(f"    Status: {status}")
        print(f"    Environment: {environment}")
        # Build config might show image
        build_config = func.get("buildConfig", {})
        source_repo = build_config.get("sourceRepository", {})
        print(f"    Source: {source_repo.get('url', 'N/A')}")
        
        # 1st gen images are usually in gcr.io/PROJECT_ID/gcf/...
        # We might need to inspect where it thinks the image is.
        # But `gcloud functions describe` might give more info.

if __name__ == "__main__":
    for p in ["altech-silence-pre", "altech-silence-dev"]:
        list_functions(p)

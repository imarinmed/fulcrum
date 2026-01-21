import sys
from typing import List
import structlog

from .runner import run_gcloud, GCloudError

log = structlog.get_logger()


def list_functions(project_id: str):
    log.info("functions.audit_start", project_id=project_id)
    functions = run_gcloud(["functions", "list", "--project", project_id])
    if not functions:
        log.warning("functions.no_functions_found", project_id=project_id)
        return

    for func in functions:
        name = func.get("name")
        runtime = func.get("runtime")
        status = func.get("status")
        # Check generation (environment)
        # 1st gen usually implies 'CLOUD_FUNCTIONS_v1' or unspecified environment?
        # 'environment' field might be 'GEN_1' or 'GEN_2'
        environment = func.get("environment", "GEN_1")

        log.info(
            "functions.function_found",
            name=name,
            runtime=runtime,
            status=status,
            environment=environment,
        )
        # Build config might show image
        build_config = func.get("buildConfig", {})
        source_repo = build_config.get("sourceRepository", {})
        source_url = source_repo.get("url", "N/A")
        log.info("functions.function_source", source=source_url)

        # 1st gen images are usually in gcr.io/PROJECT_ID/gcf/...
        # We might need to inspect where it thinks the image is.
        # But `gcloud functions describe` might give more info.


if __name__ == "__main__":
    for p in ["altech-silence-pre", "altech-silence-dev"]:
        log.info("functions.checking_project", project_id=p)
        list_functions(p)

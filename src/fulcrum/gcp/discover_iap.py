import sys
import structlog
from .runner import run_gcloud_json, GCloudError

log = structlog.get_logger()

PROJECTS = ["motit-motosharing-test", "motit-motosharing"]


def discover():
    for pid in PROJECTS:
        log.info("iap.project_check", project_id=pid)
        try:
            services = run_gcloud_json(
                ["compute", "backend-services", "list", "--project", pid]
            )
            found = 0
            for svc in services:
                name = svc.get("name")
                iap = svc.get("iap", {})
                enabled = iap.get("enabled", False)
                client_id = iap.get("oauth2ClientId")

                if enabled:
                    found += 1
                    status = "CUSTOM" if client_id else "GOOGLE-MANAGED"
                    log.info(
                        "iap.backend_service",
                        service=name,
                        enabled=enabled,
                        oauth_client=status,
                        client_id=client_id or "N/A",
                    )

            if found == 0:
                log.info("iap.no_backend_services", project_id=pid)
        except GCloudError as e:
            log.error("iap.backend_service_error", project_id=pid, error=str(e))

        # Check App Engine
        log.info("iap.app_engine_check", project_id=pid)
        try:
            settings = run_gcloud_json(
                [
                    "iap",
                    "settings",
                    "get",
                    "--project",
                    pid,
                    "--resource-type",
                    "app-engine",
                ]
            )
            # Inspect settings
            log.info("iap.app_engine_settings", project_id=pid, settings=settings)
        except GCloudError as e:
            log.warning("iap.app_engine_failed", project_id=pid, error=str(e))


if __name__ == "__main__":
    discover()

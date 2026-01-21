import subprocess
from typing import List, Optional
from .runner import run_gcloud_json, GCloudError
import structlog

log = structlog.get_logger()


class GCRMigration:
    def __init__(
        self,
        project_id: str,
        location: str = "europe-west1",
        repo_name: str = "docker-images",
    ):
        self.project_id = project_id
        self.location = location
        self.repo_name = repo_name

    def audit_gcr_images(
        self, recursive: bool = False, specific_host: Optional[str] = None
    ) -> List[str]:
        """List all images in GCR for the project.
        If recursive is True, scans sub-repositories (expensive).
        If specific_host is provided, scans only that host/path.
        """
        images = []
        hosts = (
            [specific_host]
            if specific_host
            else [f"gcr.io/{self.project_id}", f"eu.gcr.io/{self.project_id}"]
        )

        for host in hosts:
            if recursive:
                log.info("ar.audit_recursive_start", root=host)
                images.extend(self._scan_recursive(host))
            else:
                try:
                    res = run_gcloud_json(
                        ["container", "images", "list", f"--repository={host}"]
                    )
                    for item in res:
                        if "name" in item:
                            images.append(item["name"])
                except GCloudError:
                    pass
        return sorted(list(set(images)))

    def _scan_recursive(self, current_path: str) -> List[str]:
        """Recursively find images under current_path."""
        found = []
        try:
            # 1. List children
            children = run_gcloud_json(
                ["container", "images", "list", f"--repository={current_path}"]
            )

            # If we have children, recurse into them
            if children:
                for child in children:
                    name = child.get("name")
                    if name:
                        found.extend(self._scan_recursive(name))
            else:
                # 2. No children, check if it's an image (has tags)
                # Optimization: Only check if it looks like a repo path (depth?)
                # But safer to just check tags.
                if self.get_latest_tag(current_path):
                    found.append(current_path)

        except GCloudError:
            # Access denied or not a repo
            pass

        return found

    def ensure_ar_repo(self) -> str:
        """Create AR repository if not exists. Returns full repo path."""
        repo_path = f"projects/{self.project_id}/locations/{self.location}/repositories/{self.repo_name}"

        # Check if exists
        try:
            run_gcloud_json(
                [
                    "artifacts",
                    "repositories",
                    "describe",
                    self.repo_name,
                    "--project",
                    self.project_id,
                    "--location",
                    self.location,
                ]
            )
            log.info("ar.repo_exists", repo=repo_path)
            return repo_path
        except GCloudError:
            log.info("ar.repo_missing", repo=repo_path, msg="Creating repository...")

        # Create
        cmd = [
            "artifacts",
            "repositories",
            "create",
            self.repo_name,
            "--project",
            self.project_id,
            "--location",
            self.location,
            "--repository-format=docker",
            "--description=Migrated from GCR",
        ]
        run_gcloud_json(cmd)
        log.info("ar.repo_created", repo=repo_path)
        return repo_path

    def get_latest_tag(self, image_name: str) -> Optional[str]:
        """Get the most recent tag for an image."""
        try:
            # gcloud container images list-tags IMAGE --limit=1 --sort-by=~timestamp --format="value(tags)"
            # output might be comma separated if multiple tags on same digest, or empty
            res = run_gcloud_json(
                [
                    "container",
                    "images",
                    "list-tags",
                    image_name,
                    "--limit=1",
                    "--sort-by=~timestamp",
                ]
            )
            if res and len(res) > 0:
                tags = res[0].get("tags", [])
                if tags:
                    return tags[0]
                # If no tags, maybe just use digest? Docker pull by digest works.
                digest = res[0].get("digest")
                if digest:
                    return f"@{digest}"
        except GCloudError:
            pass
        return None

    def copy_image(self, gcr_image: str, dry_run: bool = False) -> str:
        """
        Copy the latest version of an image from GCR to AR using local Docker daemon.
        Returns the new AR image base URL.
        """
        # Resolve tag
        tag_or_digest = self.get_latest_tag(gcr_image)
        if not tag_or_digest:
            log.warning("ar.no_tags_found", image=gcr_image)
            return f"{gcr_image} (Skipped - No tags)"

        # Construct full source and dest
        # If tag_or_digest starts with @, it's a digest.
        separator = "@" if tag_or_digest.startswith("sha256:") else ":"
        if tag_or_digest.startswith("@"):
            separator = ""  # digest already includes @ usually? No, list-tags returns 'sha256:...'
            # Wait, get_latest_tag returns "@sha256:..." if digest
            pass

        full_src = f"{gcr_image}{separator}{tag_or_digest}"

        image_name = gcr_image.split("/")[-1]
        ar_base = f"{self.location}-docker.pkg.dev/{self.project_id}/{self.repo_name}"

        # For dest, we prefer a tag if available. If we pulled by digest, we might want to push by digest?
        # But we can't 'tag' a target with a digest. We need a tag.
        # If we only have digest, we might need to tag it as 'migrated-latest' or similar.

        target_tag = tag_or_digest if not tag_or_digest.startswith("@") else "latest"
        full_dest = f"{ar_base}/{image_name}:{target_tag}"

        log.info("ar.copy_start", src=full_src, dest=full_dest)

        if dry_run:
            return full_dest

        try:
            # 1. Pull
            subprocess.run(
                ["docker", "pull", full_src],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            # 2. Tag
            subprocess.run(
                ["docker", "tag", full_src, full_dest],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            # 3. Push
            subprocess.run(
                ["docker", "push", full_dest],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            # 4. Cleanup
            subprocess.run(
                ["docker", "rmi", full_src, full_dest],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            log.info("ar.copy_success", dest=full_dest)
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode("utf-8", errors="ignore")
            log.error("ar.copy_failed", error=err)
            raise GCloudError(f"Failed to copy {gcr_image}: {err}")

        return full_dest


def migrate_project(
    project_id: str,
    location: str,
    dry_run: bool = False,
    recursive: bool = False,
    specific_host: Optional[str] = None,
):
    migrator = GCRMigration(project_id, location)

    log.info("ar.migration_start", project_id=project_id, location=location)

    # 1. Audit
    images = migrator.audit_gcr_images(recursive=recursive, specific_host=specific_host)
    log.info("ar.audit_complete", project_id=project_id, image_count=len(images))
    if not images:
        return []

    # 2. Ensure Repo
    if not dry_run:
        migrator.ensure_ar_repo()
    else:
        log.info("ar.dry_run_repo", repo=migrator.repo_name)

    mapping = []

    # 3. Copy
    for img in images:
        log.info("ar.copy_processing", image=img)
        try:
            new_url = migrator.copy_image(img, dry_run=dry_run)
            mapping.append({"old": img, "new": new_url})
            log.info("ar.copy_mapping", source=img, dest=new_url)
        except Exception as e:
            log.error("ar.copy_failed", image=img, error=str(e))

    return mapping

import sys
from .runner import run_gcloud_json, GCloudError

PROJECTS = ["motit-motosharing-test", "motit-motosharing"]

def discover():
    for pid in PROJECTS:
        print(f"Checking project: {pid}")
        try:
            services = run_gcloud_json([
                "compute", "backend-services", "list",
                "--project", pid
            ])
            found = 0
            for svc in services:
                name = svc.get("name")
                iap = svc.get("iap", {})
                enabled = iap.get("enabled", False)
                client_id = iap.get("oauth2ClientId")
                
                if enabled:
                    found += 1
                    status = "CUSTOM" if client_id else "GOOGLE-MANAGED"
                    print(f"  - Service: {name}")
                    print(f"    IAP Enabled: {enabled}")
                    print(f"    OAuth Client: {status} ({client_id or 'N/A'})")
            
            if found == 0:
                print("  No IAP-enabled Backend Services found.")
        except GCloudError as e:
            print(f"  Error listing backend services: {e}")

        # Check App Engine
        print(f"  Checking App Engine...")
        try:
            settings = run_gcloud_json([
                "iap", "settings", "get",
                "--project", pid,
                "--resource-type", "app-engine"
            ])
            # Inspect settings
            print(f"    Settings found: {settings}")
        except GCloudError as e:
            print(f"    App Engine check failed/disabled: {e}")
            
if __name__ == "__main__":
    discover()

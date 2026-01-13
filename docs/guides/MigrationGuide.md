# Migration Guide: Adopting Secret Manager

## 1. Introduction
This guide assists developers in migrating hardcoded credentials to GCP Secret Manager, aligning with the new security policy.

## 2. Steps to Migrate

### Step 1: Identify Secrets
Run the audit tool locally to find potential leaks (or ask devOps for a report):
```bash
python3 -m src.cli security audit --path .
```

### Step 2: Create Secret in GCP
```bash
echo -n "SUPER_SECRET_VALUE" | gcloud secrets create my-service-db-pass --data-file=-
```

### Step 3: Update Application Code
**Before (Bad):**
```python
DB_PASS = "hunter2"
```

**After (Good):**
```python
import os
from google.cloud import secretmanager

def get_secret(secret_id):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

DB_PASS = get_secret("my-service-db-pass")
```

### Step 4: Verify & Clean
1. Deploy the new code.
2. Verify connection success.
3. Remove the hardcoded string from git history (use BFG Repo-Cleaner if committed).

## 3. Support
Contact the Infrastructure Team for permissions to create secrets in specific projects.

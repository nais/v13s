#!/usr/bin/env bash
#MISE description="run sql proxy for v13s db"
set -euo pipefail

if [[ -z "${1-}" ]]; then
  tenant="nav"
  echo "No tenant argument provided, using default: $tenant"
else
  tenant="$1"
  echo "Using tenant from argument: $tenant"
fi

project=$(gcloud projects list --filter='projectId~"^nais-management"' --format=json \
  | jq -er --arg prefix "$tenant" '.[] | select(.labels.tenant == $prefix) | .projectId' | head -n1)

echo "found project: $project for tenant: $tenant"

instance=$(gcloud sql instances list --project=$project --format=json \
  | jq -er '.[] | select(.name | startswith("v13s")) | .name' | head -n1)

CONNECTION_NAME=$(gcloud sql instances describe $instance --format="get(connectionName)" --project $project)
echo "connecting to instance: $CONNECTION_NAME"

cloud-sql-proxy $CONNECTION_NAME \
	    --auto-iam-authn \
	    --impersonate-service-account="v13s-sa@$project.iam.gserviceaccount.com"
#!/usr/bin/env bash

# Configure Azure and GitHub OIDC prerequisites for the Pawton demo (Defender for SQL / Sentinel).
# Creates one Entra application per GitHub Environment. No client secrets are created.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

environment_name=dev
resource_group=""
location=centralus
repository=""
subscription_id="${AZURE_SUBSCRIPTION_ID:-}"
use_defaults=false

usage() {
  cat <<'EOF'
Configure Azure and GitHub OIDC for the Pawton demo.

Usage: scripts/setup-azure-github-oidc.sh --environment <dev|prod> [options]

Options:
  --environment <name>       GitHub Environment: dev or prod (default: dev)
  --resource-group <name>    Azure resource group for the SQL VM / Web App scenario
  --location <region>        Azure region (default: centralus)
  --subscription <id>        Azure subscription (default: current az account)
  --repository <owner/name>  GitHub repository (default: current repository)
  --defaults                 Accept built-in environment defaults without prompts
  --help                     Show this help

Grants one OIDC service principal Contributor and Role Based Access Control Administrator on
the scenario's resource group, so scripts/deploy.sh (or its GitHub Actions workflow) can run
non-interactively. It creates no client secret.
EOF
}

while (($# > 0)); do
  case "$1" in
    --environment) environment_name="$2"; shift 2 ;;
    --resource-group) resource_group="$2"; shift 2 ;;
    --location) location="$2"; shift 2 ;;
    --subscription) subscription_id="$2"; shift 2 ;;
    --repository) repository="$2"; shift 2 ;;
    --defaults) use_defaults=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 1 ;;
  esac
done

for command_name in az gh tr; do
  command -v "$command_name" >/dev/null || { printf "ERROR: '%s' is required.\n" "$command_name" >&2; exit 1; }
done
command -v "$NODE_COMMAND" >/dev/null || { printf "ERROR: Node.js is required (checked for '%s').\n" "$NODE_COMMAND" >&2; exit 1; }

case "$environment_name" in
  dev)
    resource_group="${resource_group:-NP-ninjapaws-dojo-sql-Dev-CentralUS}"
    ;;
  prod)
    resource_group="${resource_group:-NP-ninjapaws-dojo-sql-Prod-CentralUS}"
    ;;
  *)
    printf '%s\n' '--environment must be dev or prod.' >&2
    exit 1
    ;;
esac

if [[ -t 0 && "$use_defaults" == false ]]; then
  location="$(prompt_region "$location")"
  read -r -p "Resource group [$resource_group]: " answer
  resource_group="${answer:-$resource_group}"
fi

az account show >/dev/null 2>&1 || { printf "%s\n" "Azure CLI is not authenticated. Run 'az login' and retry." >&2; exit 1; }
if [[ -n "$subscription_id" ]]; then
  az account set --subscription "$subscription_id"
fi
subscription_id="$(az account show --query id -o tsv)"
tenant_id="$(az account show --query tenantId -o tsv)"

gh auth status >/dev/null 2>&1 || { printf "%s\n" "GitHub CLI is not authenticated. Run 'gh auth login' and retry." >&2; exit 1; }
repository="${repository:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
repository_owner="${repository%%/*}"
repository_name="${repository#*/}"
repository_owner_id="$(gh api "users/$repository_owner" --jq .id)"
repository_id="$(gh api "repos/$repository" --jq .id)"

app_display_name="pawton-${environment_name}-github"

app_client_id="$(az ad app list --display-name "$app_display_name" --query "[?displayName=='$app_display_name'].appId | [0]" -o tsv)"
if [[ -z "$app_client_id" ]]; then
  app_client_id="$(az ad app create --display-name "$app_display_name" --sign-in-audience AzureADMyOrg --query appId -o tsv)"
fi
app_object_id="$(az ad app show --id "$app_client_id" --query id -o tsv)"

service_principal_object_id="$(az ad sp show --id "$app_client_id" --query id -o tsv 2>/dev/null || true)"
if [[ -z "$service_principal_object_id" ]]; then
  service_principal_object_id="$(az ad sp create --id "$app_client_id" --query id -o tsv)"
fi

# Jobs that declare an environment present the environment subject, not the ref subject.
# Computed by the vendored copy of pawprint's github-oidc-subject.mjs so every repo in the
# org agrees on this format byte-for-byte instead of each hand-interpolating the same string.
credential_name="github-${environment_name}"
credential_subject="$("$NODE_COMMAND" "$SCRIPT_DIR/compute-oidc-subject.mjs" "$repository_owner" "$repository_owner_id" "$repository_name" "$repository_id" "$environment_name")"
existing_credential="$(az ad app federated-credential list --id "$app_object_id" \
  --query "[?name=='$credential_name'] | [0].id" -o tsv)"
if [[ -n "$existing_credential" ]]; then
  az ad app federated-credential delete --id "$app_object_id" --federated-credential-id "$existing_credential"
fi
az ad app federated-credential create --id "$app_object_id" --parameters "$(
  printf '{"name":"%s","issuer":"https://token.actions.githubusercontent.com","subject":"%s","audiences":["api://AzureADTokenExchange"],"description":"GitHub Actions environment OIDC trust"}' \
    "$credential_name" "$credential_subject"
)" >/dev/null

az group create --name "$resource_group" --location "$location" >/dev/null

resource_group_scope="/subscriptions/$subscription_id/resourceGroups/$resource_group"
subscription_scope="/subscriptions/$subscription_id"

ensure_role() {
  local role="$1"
  local scope="$2"
  local count
  count="$(az role assignment list \
    --assignee-object-id "$service_principal_object_id" \
    --scope "$scope" \
    --query "[?roleDefinitionName=='$role'] | length(@)" -o tsv)"
  if [[ "$count" == 0 ]]; then
    az role assignment create \
      --assignee-object-id "$service_principal_object_id" \
      --assignee-principal-type ServicePrincipal \
      --role "$role" \
      --scope "$scope" \
      >/dev/null
  fi
}

ensure_role Contributor "$resource_group_scope"
ensure_role "Role Based Access Control Administrator" "$resource_group_scope"
ensure_role "Security Admin" "$subscription_scope"

echo "Configured GitHub Environment '$environment_name' for $repository:"
echo "  AZURE_CLIENT_ID=$app_client_id"
echo "  AZURE_TENANT_ID=$tenant_id"
echo "  AZURE_SUBSCRIPTION_ID=$subscription_id"
echo "  AZURE_LOCATION=$location"
echo "  Resource group: $resource_group"
echo
echo "Store the four AZURE_* values above as GitHub Environment variables (not secrets)."

#!/usr/bin/env bash

# Interactive wizard for the Pawton Defender for SQL / Sentinel demo-in-a-box.
# Wraps scripts/deploy.sh, scripts/deploy-sentinel-sql.sh, and scripts/deploy-pawton-domain.sh
# behind one guided menu so deploy, repair, and remove all live in a single entry point.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

CONFIG_FILE="${DEPLOY_CONFIG_FILE:-$REPO_ROOT/config/deploy.config.json}"

info() { echo -e "${BLUE}==>${NC} $1"; }
warn() { echo -e "${YELLOW}!${NC} $1"; }

git_branch() { git rev-parse --abbrev-ref HEAD 2>/dev/null || echo ""; }

detect_environment() {
    case "$(git_branch)" in
        main) echo prod ;;
        dev) echo dev ;;
        *) echo dev ;;
    esac
}

ENVIRONMENT="${DEPLOY_ENVIRONMENT:-$(detect_environment)}"

echo -e "${BLUE}=== Pawton — Defender for SQL / Sentinel demo wizard ===${NC}"
echo "Detected environment: $ENVIRONMENT (branch: $(git_branch))"
echo "Config file: $CONFIG_FILE"
echo

if ! command -v az >/dev/null 2>&1; then
    warn "Azure CLI (az) was not found. Plan (offline) will still work; everything else needs it."
fi

PS3=$'\nSelect an action: '
options=(
    "Plan (offline) — show what would be deployed"
    "Doctor — read-only Azure preflight checks"
    "Deploy — provision VM, SQL Server, Defender, and the Pawton dashboard"
    "Repair — re-run deploy against the existing environment (idempotent)"
    "Configure custom domain — Cloudflare DNS + HTTPS for the dashboard"
    "Deploy Sentinel analytics content — SQL detection rules on the existing workspace"
    "Uninstall — delete this environment's resource group"
    "Exit"
)

select opt in "${options[@]}"; do
    case "$REPLY" in
        1) exec bash "$SCRIPT_DIR/deploy.sh" plan --environment "$ENVIRONMENT" ;;
        2) exec bash "$SCRIPT_DIR/deploy.sh" doctor --environment "$ENVIRONMENT" ;;
        3)
            read -r -p "Deploy environment '$ENVIRONMENT'? [y/N] " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
            exec bash "$SCRIPT_DIR/deploy.sh" deploy --environment "$ENVIRONMENT"
            ;;
        4)
            info "Repair re-runs deploy: idempotent bootstrap repairs missing audit specs, extensions, and secrets."
            read -r -p "Repair environment '$ENVIRONMENT'? [y/N] " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
            exec bash "$SCRIPT_DIR/deploy.sh" deploy --environment "$ENVIRONMENT" --yes
            ;;
        5) exec bash "$SCRIPT_DIR/deploy.sh" domain --environment "$ENVIRONMENT" ;;
        6)
            echo "Sentinel content lifecycle: plan, doctor, what-if, deploy, verify."
            read -r -p "Stage [plan]: " stage
            stage="${stage:-plan}"
            exec bash "$SCRIPT_DIR/deploy-sentinel-sql.sh" "$stage" --environment "$ENVIRONMENT"
            ;;
        7)
            resource_group="$(config_lookup "environments.${ENVIRONMENT}.sqlResourceGroup")"
            resource_group="${resource_group:-NP-ninjapaws-dojo-sql-${ENVIRONMENT}}"
            warn "This deletes the resource group '$resource_group' and everything in it."
            read -r -p "Type the exact resource group name to confirm: " confirm_name
            [[ "$confirm_name" == "$resource_group" ]] || { echo "Name did not match. Cancelled."; exit 1; }
            exec bash "$SCRIPT_DIR/deploy.sh" uninstall --environment "$ENVIRONMENT" --resource-group "$resource_group" --yes
            ;;
        8) exit 0 ;;
        *) echo "Invalid selection." ;;
    esac
done

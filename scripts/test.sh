#!/usr/bin/env bash

# Cross-platform repository checks for the Pawton demo (Linux, macOS, WSL, Git Bash).

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
SKIP_AZURE=false

usage() {
    cat <<'EOF'
Run cross-platform deployment and infrastructure checks.

Usage: scripts/test.sh [--skip-azure]

Options:
  --skip-azure  Skip Azure CLI/Bicep checks when az is unavailable
EOF
}

while (($# > 0)); do
    case "$1" in
        --skip-azure) SKIP_AZURE=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

for command_name in bash git; do
    command -v "$command_name" >/dev/null 2>&1 || { echo "ERROR: '$command_name' is required." >&2; exit 1; }
done
if ! command -v "$NODE_COMMAND" >/dev/null 2>&1; then
    echo "ERROR: Node.js is required for ARM JSON checks." >&2
    exit 1
fi

echo "Checking Bash syntax..."
bash -n "$REPO_ROOT/scripts/deploy.sh"
bash -n "$REPO_ROOT/scripts/deploy-sentinel-sql.sh"
bash -n "$REPO_ROOT/scripts/deploy-pawton-domain.sh"
bash -n "$REPO_ROOT/scripts/lib/common.sh"
bash -n "$REPO_ROOT/scripts/manage.sh"
bash -n "$REPO_ROOT/scripts/setup-azure-github-oidc.sh"
bash -n "$REPO_ROOT/scripts/test.sh"

echo "Checking Node.js runtime syntax..."
(
    cd "$REPO_ROOT"
    "$NODE_COMMAND" --check scripts/compute-oidc-subject.mjs
    "$NODE_COMMAND" --check scripts/configure-pawton-dns.mjs
    "$NODE_COMMAND" --check scripts/run-sql-attack-test.mjs
    "$NODE_COMMAND" --check scripts/lib/sql-credentials.mjs
    "$NODE_COMMAND" --check scripts/serve-external-source-canary.mjs
    "$NODE_COMMAND" --check scripts/verify-unique-canary.mjs
    "$NODE_COMMAND" --check scripts/test-walkthrough.mjs
    "$NODE_COMMAND" scripts/test-sentinel-sql.mjs
    "$NODE_COMMAND" --test scripts/test-pawton-domain.mjs
)

echo "Checking ARM JSON..."
"$NODE_COMMAND" -e "for (const file of ['infra/sql-defender-scenario/main.json', 'infra/sql-canary/main.json', 'infra/sentinel-sql-solution/main.json', 'azuredeploy.json']) JSON.parse(require('fs').readFileSync(file, 'utf8'));"

echo "Checking package release metadata..."
"$NODE_COMMAND" - <<'NODE'
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
if (pkg.name !== 'pawton') throw new Error('package name drift');
if (!pkg.description || !pkg.repository || !pkg.repository.url.includes(pkg.name)) throw new Error('package repository metadata drift');
if (pkg.license !== 'MIT') throw new Error('package identity metadata drift');
NODE

test -f "$REPO_ROOT/apps/pawton-manufacturing/package.json"
test -f "$REPO_ROOT/apps/pawton-manufacturing/astro.config.mjs"
test -f "$REPO_ROOT/azuredeploy.json"
test -f "$REPO_ROOT/config/deploy.config.json"

if [[ "$SKIP_AZURE" == false ]]; then
    if command -v az >/dev/null 2>&1 && az bicep version >/dev/null 2>&1; then
        # Mirrors the kit-bicep-validate workflow so a green local run means a green CI run:
        # every template is linted (warnings are failures) and every committed ARM sibling is
        # checked for drift. Compiling only the entry-point templates previously let a
        # hand-edited main.json reach the branch without anything noticing.
        echo "Compiling and linting Bicep templates..."
        bicep_failed=false
        while IFS= read -r bicep_file; do
            rel_path="${bicep_file#"$REPO_ROOT/"}"
            build_stderr="$(mktemp)"
            build_stdout="$(mktemp)"
            if ! az bicep build --file "$bicep_file" --stdout >"$build_stdout" 2>"$build_stderr"; then
                echo "  FAIL  $rel_path did not compile:" >&2
                cat "$build_stderr" >&2
                bicep_failed=true
                rm -f "$build_stderr" "$build_stdout"
                continue
            fi
            # Bicep reports findings as "<file>(line,col) : Warning <code>: <message>". The
            # "Info" lines about a custom bicepconfig.json are notices, not findings.
            if grep -Eq ': (Warning|Error) ' "$build_stderr"; then
                echo "  FAIL  $rel_path has lint findings:" >&2
                grep -E ': (Warning|Error) ' "$build_stderr" >&2
                bicep_failed=true
            fi

            # Templates with a committed ARM sibling must match what the compiler produces now.
            arm_sibling="${bicep_file%.bicep}.json"
            if [[ -f "$arm_sibling" ]]; then
                if ! "$NODE_COMMAND" -e '
                    const fs = require("fs");
                    const sortKeys = (value) =>
                        Array.isArray(value)
                            ? value.map(sortKeys)
                            : value && typeof value === "object"
                              ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]))
                              : value;
                    const read = (file) => JSON.stringify(sortKeys(JSON.parse(fs.readFileSync(file, "utf8"))));
                    process.exit(read(process.argv[1]) === read(process.argv[2]) ? 0 : 1);
                ' "$build_stdout" "$arm_sibling"; then
                    echo "  FAIL  ${arm_sibling#"$REPO_ROOT/"} is stale; regenerate it with 'az bicep build --file $rel_path --outfile ${arm_sibling#"$REPO_ROOT/"}'." >&2
                    bicep_failed=true
                fi
            fi
            rm -f "$build_stderr" "$build_stdout"
        done < <(find "$REPO_ROOT/infra" -name '*.bicep' | sort)

        if [[ "$bicep_failed" == true ]]; then
            echo "Bicep validation failed." >&2
            exit 1
        fi
    else
        echo "Azure CLI/Bicep unavailable; skipping compilation. Re-run without --skip-azure once installed." >&2
    fi
fi

echo "All checks passed."

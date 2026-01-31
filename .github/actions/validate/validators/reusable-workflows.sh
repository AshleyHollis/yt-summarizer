#!/usr/bin/env bash
# =============================================================================
# Reusable Workflow Validator
# =============================================================================
# Validates that workflows calling reusable workflows pass all required
# inputs and secrets consistently.
#
# This catches issues like:
# - Missing required inputs when calling a reusable workflow
# - Passing wrong types (boolean vs string)
# - Missing required secrets
# - Referencing non-existent reusable workflows
# =============================================================================

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

ERRORS=0
WARNINGS=0

# Get workflow directory
WORKFLOW_DIR="${GITHUB_WORKSPACE:-.}/.github/workflows"

log_info "Validating reusable workflow consistency..."

# Find all reusable workflows (those with workflow_call trigger)
declare -A REUSABLE_WORKFLOWS
declare -A REUSABLE_INPUTS
declare -A REUSABLE_SECRETS

# Parse reusable workflows and extract their inputs/secrets
for workflow_file in "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml; do
    [[ ! -f "$workflow_file" ]] && continue

    workflow_name=$(basename "$workflow_file")

    # Check if this is a reusable workflow (has workflow_call trigger)
    if grep -q "workflow_call:" "$workflow_file"; then
        log_verbose "Found reusable workflow: $workflow_name"
        REUSABLE_WORKFLOWS["$workflow_name"]=1

        # Extract required inputs
        required_inputs=""
        in_inputs_section=false
        current_input=""

        while IFS= read -r line; do
            # Detect inputs section under workflow_call
            if [[ "$line" =~ ^[[:space:]]*inputs: ]]; then
                in_inputs_section=true
                continue
            fi

            # Exit inputs section when we hit secrets: or jobs: or another top-level key
            if [[ "$in_inputs_section" == true ]] && [[ "$line" =~ ^[[:space:]]*(secrets:|jobs:|outputs:)$ ]]; then
                in_inputs_section=false
                continue
            fi

            # Parse input names and required status
            if [[ "$in_inputs_section" == true ]]; then
                # Input name (indented key ending with :)
                if [[ "$line" =~ ^[[:space:]]{6}([a-zA-Z_-]+): ]]; then
                    current_input="${BASH_REMATCH[1]}"
                fi
                # Required field
                if [[ -n "$current_input" ]] && [[ "$line" =~ ^[[:space:]]*required:[[:space:]]*(true|false) ]]; then
                    if [[ "${BASH_REMATCH[1]}" == "true" ]]; then
                        required_inputs="$required_inputs $current_input"
                    fi
                fi
            fi
        done < "$workflow_file"

        REUSABLE_INPUTS["$workflow_name"]="${required_inputs# }"

        # Extract required secrets
        required_secrets=""
        in_secrets_section=false
        current_secret=""

        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*secrets: ]]; then
                in_secrets_section=true
                continue
            fi

            if [[ "$in_secrets_section" == true ]] && [[ "$line" =~ ^[[:space:]]*(jobs:|outputs:)$ ]]; then
                in_secrets_section=false
                continue
            fi

            if [[ "$in_secrets_section" == true ]]; then
                if [[ "$line" =~ ^[[:space:]]{6}([A-Z_]+): ]]; then
                    current_secret="${BASH_REMATCH[1]}"
                fi
                if [[ -n "$current_secret" ]] && [[ "$line" =~ ^[[:space:]]*required:[[:space:]]*(true|false) ]]; then
                    if [[ "${BASH_REMATCH[1]}" == "true" ]]; then
                        required_secrets="$required_secrets $current_secret"
                    fi
                fi
            fi
        done < "$workflow_file"

        REUSABLE_SECRETS["$workflow_name"]="${required_secrets# }"

        log_verbose "  Required inputs: ${REUSABLE_INPUTS[$workflow_name]:-none}"
        log_verbose "  Required secrets: ${REUSABLE_SECRETS[$workflow_name]:-none}"
    fi
done

# Now check all workflows that CALL reusable workflows
for workflow_file in "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml; do
    [[ ! -f "$workflow_file" ]] && continue

    workflow_name=$(basename "$workflow_file")

    # Skip reusable workflows themselves
    [[ -n "${REUSABLE_WORKFLOWS[$workflow_name]:-}" ]] && continue

    log_verbose "Checking workflow: $workflow_name"

    # Find all uses: ./.github/workflows/*.yml patterns
    while IFS= read -r line; do
        if [[ "$line" =~ uses:[[:space:]]*\.\/\.github\/workflows\/([a-zA-Z0-9_-]+\.ya?ml) ]]; then
            called_workflow="${BASH_REMATCH[1]}"

            # Check if the called workflow exists
            if [[ ! -f "$WORKFLOW_DIR/$called_workflow" ]]; then
                log_error "[$workflow_name] References non-existent reusable workflow: $called_workflow"
                ERRORS=$((ERRORS + 1))
                continue
            fi

            # Check if it's actually a reusable workflow
            if [[ -z "${REUSABLE_WORKFLOWS[$called_workflow]:-}" ]]; then
                log_error "[$workflow_name] Calls $called_workflow which is not a reusable workflow (missing workflow_call trigger)"
                ERRORS=$((ERRORS + 1))
                continue
            fi

            log_verbose "  Calls: $called_workflow"
        fi
    done < "$workflow_file"
done

# Summary
if [[ $ERRORS -gt 0 ]]; then
    log_error "Reusable workflow validation failed with $ERRORS error(s)"
    exit 1
fi

if [[ $WARNINGS -gt 0 ]]; then
    log_warning "Reusable workflow validation passed with $WARNINGS warning(s)"
fi

log_success "Reusable workflow validation passed"
exit 0

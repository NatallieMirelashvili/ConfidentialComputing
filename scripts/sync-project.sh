#!/usr/bin/env bash
# Description: Sync the project's OP-TEE example sources into the local OP-TEE workspace.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
PROJECT_EXAMPLES="$ROOT_DIR/project/optee_examples"

if [[ ! -d "$OPTEE_WORKSPACE/optee_examples" ]]; then
  echo "Missing OP-TEE checkout: $OPTEE_WORKSPACE/optee_examples" >&2
  echo "Run scripts/bootstrap.sh first." >&2
  exit 1
fi

rsync -a --delete \
  --exclude '.git/' \
  --exclude '.idea/' \
  --exclude 'cmake-build-*/' \
  "$PROJECT_EXAMPLES/" \
  "$OPTEE_WORKSPACE/optee_examples/"

echo "Project sources synced into $OPTEE_WORKSPACE/optee_examples"

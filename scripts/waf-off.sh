#!/usr/bin/env bash
# Turn the shield OFF: disassociate the WAF web ACL from the API stage.
# This is how the demo STARTS (unprotected). source scripts/arns.env first.
set -euo pipefail

AWS="${AWS:-aws}"
: "${STAGE_ARN:?set STAGE_ARN (source scripts/arns.env)}"

echo "Disassociating WAF web ACL from the API stage..."
"$AWS" wafv2 disassociate-web-acl \
  --resource-arn "$STAGE_ARN" \
  --region "${AWS_REGION:-us-east-1}"

echo "SHIELD OFF. Propagation takes ~30-60s. Flip the dashboard toggle to OFF."

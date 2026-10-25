#!/usr/bin/env bash
# Turn the shield ON: associate the WAF web ACL with the API stage.
# Fill scripts/arns.env from the cdk outputs first, then: source scripts/arns.env
set -euo pipefail

AWS="${AWS:-aws}"
: "${WEBACL_ARN:?set WEBACL_ARN (source scripts/arns.env)}"
: "${STAGE_ARN:?set STAGE_ARN (source scripts/arns.env)}"

echo "Associating WAF web ACL with the API stage..."
"$AWS" wafv2 associate-web-acl \
  --web-acl-arn "$WEBACL_ARN" \
  --resource-arn "$STAGE_ARN" \
  --region "${AWS_REGION:-us-east-1}"

echo "SHIELD ON. Propagation takes ~30-60s. Flip the dashboard toggle to ON."

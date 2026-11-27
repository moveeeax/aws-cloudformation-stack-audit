#!/usr/bin/env bash
# Collect the dumps aws-cloudformation-stack-audit reads, for one region.
# Usage: ./collect-dumps.sh eu-west-1 dumps/
set -euo pipefail

region="${1:?usage: collect-dumps.sh <region> [out-dir]}"
out="${2:-dumps}"
mkdir -p "$out"

aws cloudformation describe-stacks --region "$region" > "$out/stacks.json"

# Resource dumps are what make the termination-protection and IAM checks work:
# without them the tool cannot tell a stack holding an RDS instance from one
# holding a single Lambda, and it stays quiet rather than guessing.
aws cloudformation describe-stacks --region "$region" \
  --query 'Stacks[?StackStatus!=`DELETE_COMPLETE`].StackName' --output text \
| tr '\t' '\n' \
| while read -r stack; do
    [ -n "$stack" ] || continue
    aws cloudformation describe-stack-resources \
      --region "$region" --stack-name "$stack" > "$out/$stack-resources.json"
  done

echo "wrote dumps to $out/"

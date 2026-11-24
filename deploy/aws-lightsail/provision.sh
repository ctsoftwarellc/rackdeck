#!/usr/bin/env bash
set -euo pipefail

# Provision the ~$17.50/mo AWS Lightsail production stack:
#   - Control Plane: $10/mo (2 GB RAM, 2 vCPU, 60 GB SSD, 3 TB transfer)
#   - Connect Relay: $7/mo  (1 GB RAM, 2 vCPU, 40 GB SSD, 2 TB transfer)
#   - Litestream S3: ~$0.50/mo

REGION="${AWS_REGION:-us-east-1}"
AZ="${REGION}a"
BUCKET="${RACKDECK_BACKUP_BUCKET:-rackdeck-backups-prod}"

echo "Creating Lightsail Control Plane ($10/mo)..."
aws lightsail create-instances \
  --region "$REGION" \
  --instance-names rackdeck-control-1 \
  --availability-zone "$AZ" \
  --blueprint-id ubuntu_24_04 \
  --bundle-id small_3_0

echo "Creating Lightsail Rackdeck Connect Relay ($7/mo, 2 TB transfer)..."
aws lightsail create-instances \
  --region "$REGION" \
  --instance-names rackdeck-relay-use1 \
  --availability-zone "$AZ" \
  --blueprint-id ubuntu_24_04 \
  --bundle-id micro_3_0

echo "Opening HTTPS/HTTP ports..."
for NAME in rackdeck-control-1 rackdeck-relay-use1; do
  aws lightsail open-instance-public-ports --region "$REGION" --instance-name "$NAME" --port-info fromPort=80,toPort=80,protocol=TCP
  aws lightsail open-instance-public-ports --region "$REGION" --instance-name "$NAME" --port-info fromPort=443,toPort=443,protocol=TCP
done

echo "Creating S3 bucket for Litestream SQLite replication..."
aws s3 mb "s3://${BUCKET}" --region "$REGION" || true
echo "Done. Attach static IPs in Lightsail, point Cloudflare DNS, and install systemd units."

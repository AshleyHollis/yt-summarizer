#!/usr/bin/env bash
set -euo pipefail

MODE="${1:?Usage: openclaw-preview-dns.sh <upsert|delete> <hostname>}"
HOSTNAME="${2:?Usage: openclaw-preview-dns.sh <upsert|delete> <hostname>}"

: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"

ZONE_NAME="${CLOUDFLARE_ZONE_NAME:-ashleyhollis.com}"
TARGET_RECORD="${CLOUDFLARE_TUNNEL_TARGET_RECORD:-api-ytsummarizer.ashleyhollis.com}"
API_BASE="https://api.cloudflare.com/client/v4"

cf_get() {
  local url="$1"
  shift
  curl -fsS \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    -H "Content-Type: application/json" \
    "$url" \
    "$@"
}

cf_write() {
  local method="$1"
  local url="$2"
  local body="$3"
  curl -fsS \
    -X "$method" \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "$body" \
    "$url"
}

zone_response="$(cf_get "${API_BASE}/zones" --get --data-urlencode "name=${ZONE_NAME}")"
zone_id="$(jq -r '.result[0].id // empty' <<<"${zone_response}")"
if [[ -z "${zone_id}" ]]; then
  echo "::error::Cloudflare zone not found: ${ZONE_NAME}"
  exit 1
fi

record_response="$(cf_get "${API_BASE}/zones/${zone_id}/dns_records" \
  --get \
  --data-urlencode "name=${HOSTNAME}" \
  --data-urlencode "type=CNAME")"
record_id="$(jq -r '.result[0].id // empty' <<<"${record_response}")"

if [[ "${MODE}" == "delete" ]]; then
  if [[ -z "${record_id}" ]]; then
    echo "No Cloudflare DNS record found for ${HOSTNAME}; nothing to delete."
    exit 0
  fi

  delete_response="$(cf_write DELETE "${API_BASE}/zones/${zone_id}/dns_records/${record_id}" "{}")"
  if [[ "$(jq -r '.success' <<<"${delete_response}")" != "true" ]]; then
    echo "::error::Failed to delete Cloudflare DNS record for ${HOSTNAME}: $(jq -c '.errors' <<<"${delete_response}")"
    exit 1
  fi

  echo "Deleted Cloudflare DNS record for ${HOSTNAME}."
  exit 0
fi

if [[ "${MODE}" != "upsert" ]]; then
  echo "::error::Unsupported mode: ${MODE}"
  exit 1
fi

target_response="$(cf_get "${API_BASE}/zones/${zone_id}/dns_records" \
  --get \
  --data-urlencode "name=${TARGET_RECORD}" \
  --data-urlencode "type=CNAME")"
target_content="$(jq -r '.result[0].content // empty' <<<"${target_response}")"
if [[ -z "${target_content}" ]]; then
  echo "::error::Cloudflare tunnel target record not found: ${TARGET_RECORD}"
  exit 1
fi

body="$(jq -nc \
  --arg name "${HOSTNAME}" \
  --arg content "${target_content}" \
  '{
    type: "CNAME",
    name: $name,
    content: $content,
    ttl: 1,
    proxied: true,
    comment: "Managed by yt-summarizer preview workflow"
  }')"

if [[ -n "${record_id}" ]]; then
  response="$(cf_write PUT "${API_BASE}/zones/${zone_id}/dns_records/${record_id}" "${body}")"
  action="Updated"
else
  response="$(cf_write POST "${API_BASE}/zones/${zone_id}/dns_records" "${body}")"
  action="Created"
fi

if [[ "$(jq -r '.success' <<<"${response}")" != "true" ]]; then
  echo "::error::Failed to upsert Cloudflare DNS record for ${HOSTNAME}: $(jq -c '.errors' <<<"${response}")"
  exit 1
fi

echo "${action} Cloudflare DNS record ${HOSTNAME} -> ${target_content}."

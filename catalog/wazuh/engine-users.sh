#!/usr/bin/env bash
set -euo pipefail

CERTS="${CERTS:-/etc/wazuh-indexer/certs}"
INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
INDEXER_CA="${INDEXER_CA:-$CERTS/root-ca.pem}"
INDEXER_ADMIN="${INDEXER_ADMIN:-admin}"
KEEP_PASSWORDS="${KEEP_PASSWORDS:-0}"
INDEXER_RESOLVE="${INDEXER_RESOLVE:-}"
API_URL="${API_URL:-https://127.0.0.1:55000}"
API_ADMIN="${API_ADMIN:-wazuh-wui}"
ENV_FILE="${ENV_FILE:-/etc/oscompliance/engine.env}"
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() {
  echo "usage: engine-users.sh create | remove" >&2
  exit 1
}

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "$tool is not installed" >&2; exit 2; }
done

indexer_auth() {
  if [ -f "$CERTS/admin.pem" ] && [ -f "$CERTS/admin-key.pem" ]; then
    INDEXER_AUTH=(--cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem")
    return
  fi
  local password
  password="$(read_secret "Password of the indexer user $INDEXER_ADMIN" "${INDEXER_ADMIN_PASSWORD:-}")"
  INDEXER_HEADERS="$(mktemp)"
  trap 'rm -f "$INDEXER_HEADERS"' EXIT
  printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "$INDEXER_ADMIN" "$password" | base64 | tr -d '\n')" > "$INDEXER_HEADERS"
  INDEXER_AUTH=(-H "@$INDEXER_HEADERS")
}

indexer() {
  local resolve=()
  [ -z "$INDEXER_RESOLVE" ] || resolve=(--resolve "$INDEXER_RESOLVE")
  curl -sS --fail-with-body ${resolve[@]+"${resolve[@]}"} --cacert "$INDEXER_CA" "${INDEXER_AUTH[@]}" \
    -H 'Content-Type: application/json' "$@"
}

api() {
  curl -sSk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"
}

read_secret() {
  local prompt="$1" value="${2:-}"
  if [ -z "$value" ]; then
    read -rsp "$prompt: " value || { echo >&2; echo "no terminal to ask for it: export the password in the environment, see install.md" >&2; exit 4; }
    echo >&2
  fi
  printf '%s' "$value"
}

api_login() {
  local admin_password
  admin_password="$(read_secret "Password of the Wazuh API user $API_ADMIN" "${API_ADMIN_PASSWORD:-}")"
  TOKEN="$(curl -sSk -u "$API_ADMIN:$admin_password" -X POST "$API_URL/security/user/authenticate?raw=true")"
  case "$TOKEN" in
    ey*) ;;
    *) echo "the Wazuh API refused the login: $TOKEN" >&2; exit 3 ;;
  esac
}

api_id() {
  api "$API_URL/security/$1?limit=500" \
    | jq -r --arg key "$2" --arg name "$3" '.data.affected_items[] | select(.[$key] == $name) | .id'
}

ask_password() {
  local value
  value="$(read_secret "$1" "${2:-}")"
  case "$value" in
    *[\$\&\'\"\\\ ]*) echo "the password cannot hold \$, &, quotes, backslashes or spaces" >&2; exit 4 ;;
  esac
  printf '%s' "$value"
}

create() {
  local indexer_password api_password policy role user
  if [ "$KEEP_PASSWORDS" = 1 ] && [ -f "$ENV_FILE" ]; then
    indexer_password="$(sed -n 's/^OSC_INDEXER_PASSWORD=//p' "$ENV_FILE")"
    api_password="$(sed -n 's/^OSC_WAZUH_API_PASSWORD=//p' "$ENV_FILE")"
  else
    indexer_password="$(ask_password 'New password of the oscompliance indexer user' "${OSC_INDEXER_PASSWORD:-}")"
    api_password="$(ask_password 'New password of the oscompliance Wazuh API user' "${OSC_WAZUH_API_PASSWORD:-}")"
  fi

  indexer_auth

  indexer -o /dev/null -X PUT "$INDEXER_URL/_plugins/_security/api/roles/oscompliance_engine" \
    -d @"$HERE/engine-role.json"
  jq -n --arg password "$indexer_password" '{password: $password}' \
    | indexer -o /dev/null -X PUT "$INDEXER_URL/_plugins/_security/api/internalusers/oscompliance" -d @-
  indexer -o /dev/null -X PUT "$INDEXER_URL/_plugins/_security/api/rolesmapping/oscompliance_engine" \
    -d '{"users": ["oscompliance"]}'
  echo "indexer: role and user oscompliance ready"

  api_login
  policy="$(api_id policies name oscompliance_engine_groups)"
  if [ -n "$policy" ]; then
    api -o /dev/null -X PUT "$API_URL/security/policies/$policy" -d "$(jq .policy "$HERE/engine-api-role.json")"
  else
    policy="$(api -X POST "$API_URL/security/policies" -d "$(jq .policy "$HERE/engine-api-role.json")" | jq -r '.data.affected_items[0].id')"
  fi
  role="$(api_id roles name oscompliance_engine)"
  [ -n "$role" ] || role="$(api -X POST "$API_URL/security/roles" -d '{"name": "oscompliance_engine"}' | jq -r '.data.affected_items[0].id')"
  api -o /dev/null -X POST "$API_URL/security/roles/$role/policies?policy_ids=$policy"
  user="$(api_id users username oscompliance)"
  if [ -n "$user" ]; then
    jq -n --arg password "$api_password" '{password: $password}' \
      | api -o /dev/null -X PUT "$API_URL/security/users/$user" -d @-
  else
    user="$(jq -n --arg password "$api_password" '{username: "oscompliance", password: $password}' \
      | api -X POST "$API_URL/security/users" -d @- | jq -r '.data.affected_items[0].id')"
  fi
  case "$user" in
    ''|null) echo "the Wazuh API refused the user: its password needs 8 to 64 characters with upper and lower case, a digit and a symbol" >&2; exit 5 ;;
  esac
  api -o /dev/null -X POST "$API_URL/security/users/$user/roles?role_ids=$role"
  echo "Wazuh API: policy, role and user oscompliance ready"

  mkdir -p "$(dirname "$ENV_FILE")"
  ( umask 077
    printf 'OSC_INDEXER_PASSWORD=%s\nOSC_WAZUH_API_PASSWORD=%s\n' "$indexer_password" "$api_password" > "$ENV_FILE" )
  echo "credentials written to $ENV_FILE"
}

remove() {
  local id
  indexer_auth
  for path in internalusers/oscompliance rolesmapping/oscompliance_engine roles/oscompliance_engine; do
    curl_status="$(indexer -o /dev/null -w '%{http_code}' -X DELETE "$INDEXER_URL/_plugins/_security/api/$path" || true)"
    echo "indexer: $path $curl_status"
  done

  api_login
  id="$(api_id users username oscompliance)"
  [ -z "$id" ] || api -o /dev/null -X DELETE "$API_URL/security/users?user_ids=$id"
  id="$(api_id roles name oscompliance_engine)"
  [ -z "$id" ] || api -o /dev/null -X DELETE "$API_URL/security/roles?role_ids=$id"
  id="$(api_id policies name oscompliance_engine_groups)"
  [ -z "$id" ] || api -o /dev/null -X DELETE "$API_URL/security/policies?policy_ids=$id"
  echo "Wazuh API: policy, role and user oscompliance removed"

  rm -f "$ENV_FILE"
}

[ $# -eq 1 ] || usage
case "$1" in
  create) create ;;
  remove) remove ;;
  *) usage ;;
esac

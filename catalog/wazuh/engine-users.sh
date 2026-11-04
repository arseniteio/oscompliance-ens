#!/usr/bin/env bash
set -euo pipefail

CERTS="${CERTS:-/etc/wazuh-indexer/certs}"
INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
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

indexer() {
  local resolve=()
  [ -z "$INDEXER_RESOLVE" ] || resolve=(--resolve "$INDEXER_RESOLVE")
  curl -sS --fail-with-body ${resolve[@]+"${resolve[@]}"} --cacert "$CERTS/root-ca.pem" \
    --cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem" \
    -H 'Content-Type: application/json' "$@"
}

api() {
  curl -sSk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"
}

api_login() {
  read -rsp "Password of the Wazuh API user $API_ADMIN: " admin_password; echo
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
  local prompt="$1" value
  read -rsp "$prompt: " value; echo >&2
  case "$value" in
    *[\$\&\'\"\\\ ]*) echo "the password cannot hold \$, &, quotes, backslashes or spaces" >&2; exit 4 ;;
  esac
  printf '%s' "$value"
}

create() {
  local indexer_password api_password policy role user
  indexer_password="$(ask_password 'New password of the oscompliance indexer user')"
  api_password="$(ask_password 'New password of the oscompliance Wazuh API user')"

  indexer -o /dev/null -X PUT "$INDEXER_URL/_plugins/_security/api/roles/oscompliance_engine" \
    -d @"$HERE/engine-role.json"
  jq -n --arg password "$indexer_password" '{password: $password}' \
    | indexer -o /dev/null -X PUT "$INDEXER_URL/_plugins/_security/api/internalusers/oscompliance" -d @-
  indexer -o /dev/null -X PUT "$INDEXER_URL/_plugins/_security/api/rolesmapping/oscompliance_engine" \
    -d '{"users": ["oscompliance"]}'
  echo "indexer: role and user oscompliance ready"

  api_login
  policy="$(api_id policies name oscompliance_engine_groups)"
  [ -n "$policy" ] || policy="$(api -X POST "$API_URL/security/policies" -d "$(jq .policy "$HERE/engine-api-role.json")" | jq -r '.data.affected_items[0].id')"
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

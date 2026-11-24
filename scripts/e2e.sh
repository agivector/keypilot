#!/usr/bin/env sh

# Description: Builds KeyPilot, provisions shared vector keys, and runs all SDK examples.
# Author: vectorshi
# Created: 2026-11-25

set -eu

IMAGE_NAME="keypilot:e2e"
CONTAINER_NAME="keypilot-e2e-$$"
ADMIN_TOKEN="keypilot-e2e-admin-token"
ISSUER="vector-issuer"
TEMP_DIR="$(mktemp -d)"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# cleanup removes temporary files and the isolated KeyPilot container.
#
# Author: vectorshi
# Created: 2026-11-25
# Parameters: None.
# Returns: None.
cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$TEMP_DIR"
}

trap cleanup EXIT INT TERM

docker build -t "$IMAGE_NAME" "$ROOT_DIR"
docker run -d --name "$CONTAINER_NAME" -p 127.0.0.1::8080 \
  -e KEYPILOT_ADMIN_ID="e2e-operator" \
  -e KEYPILOT_ADMIN_TOKEN="$ADMIN_TOKEN" "$IMAGE_NAME" >/dev/null

HOST_PORT="$(docker port "$CONTAINER_NAME" 8080/tcp | sed 's/.*://')"
BASE_URL="http://127.0.0.1:$HOST_PORT"
SDK_JWKS_URL="http://127.0.0.1:8080/v1/issuers/$ISSUER/.well-known/jwks.json"

attempt=0
until curl -fsS "$BASE_URL/readyz" >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "KeyPilot did not become healthy" >&2
    exit 1
  fi
  sleep 1
done

curl -fsS -X POST "$BASE_URL/admin/v1/issuers" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"issuer\":\"$ISSUER\",\"displayName\":\"Vector Issuer\"}" >/dev/null

python3 - "$ROOT_DIR/test-vectors/keys/rsa-public-jwks.json" "$TEMP_DIR" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
for index, key in enumerate(json.loads(source.read_text(encoding="utf-8"))["keys"]):
    (target / f"key-{index}.json").write_text(json.dumps({"jwk": key}), encoding="utf-8")
PY

for key_file in "$TEMP_DIR"/key-*.json; do
  kid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["jwk"]["kid"])' "$key_file")"
  curl -fsS -X POST "$BASE_URL/admin/v1/issuers/$ISSUER/keys" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    --data-binary "@$key_file" >/dev/null
  curl -fsS -X PATCH "$BASE_URL/admin/v1/issuers/$ISSUER/keys/$kid/status" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"status":2}' >/dev/null
done

docker run --rm --network "container:$CONTAINER_NAME" \
  -e KEYPILOT_EXAMPLE_JWKS_URL="$SDK_JWKS_URL" \
  -e GOCACHE=/tmp/go-cache -e GOPATH=/tmp/go \
  -v "$ROOT_DIR:/workspace:ro" -w /workspace/examples/go \
  golang:1.24-alpine go run .

docker run --rm --network "container:$CONTAINER_NAME" \
  -e KEYPILOT_EXAMPLE_JWKS_URL="$SDK_JWKS_URL" \
  -e PYTHONPYCACHEPREFIX=/tmp/pycache \
  -v "$ROOT_DIR:/workspace:ro" -w /workspace/examples/python \
  python:3.12-slim sh -c 'pip install --quiet --root-user-action=ignore "cryptography>=42,<47" && PYTHONPATH=/workspace/sdk/python/src python verify.py'

docker run --rm --network "container:$CONTAINER_NAME" \
  -e KEYPILOT_EXAMPLE_JWKS_URL="$SDK_JWKS_URL" \
  -v "$ROOT_DIR:/workspace:ro" \
  maven:3.9.11-eclipse-temurin-21 sh -c '
    cp -R /workspace/sdk/java /tmp/sdk-java &&
    cp -R /workspace/examples/java /tmp/example-java &&
    mvn -q -Dmaven.repo.local=/tmp/m2 -f /tmp/sdk-java/pom.xml install -DskipTests &&
    mvn -q -Dmaven.repo.local=/tmp/m2 -f /tmp/example-java/pom.xml compile exec:java
  '

echo "KeyPilot Docker end-to-end verification passed for Go, Python, and Java SDKs."

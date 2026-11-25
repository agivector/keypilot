#!/usr/bin/env sh

# Description: Verifies that all public SDKs use one release version and expected package identities.
# Author: vectorshi
# Created: 2026-11-25

set -eu

ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
EXPECTED_TAG="v$VERSION"
ACTUAL_TAG="${1:-}"
if [ -z "$ACTUAL_TAG" ] && [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  ACTUAL_TAG="${GITHUB_REF_NAME:-}"
fi

# fail reports one release metadata mismatch.
#
# Author: vectorshi
# Created: 2026-11-25
# Parameters:
#   - message: human-readable validation error.
# Returns: None.
fail() {
  echo "release validation failed: $1" >&2
  exit 1
}

[ -n "$VERSION" ] || fail "VERSION is empty"
if [ -n "$ACTUAL_TAG" ] && [ "$ACTUAL_TAG" != "$EXPECTED_TAG" ]; then
  fail "tag $ACTUAL_TAG does not match $EXPECTED_TAG"
fi

python3 - "$ROOT_DIR" "$VERSION" <<'PY'
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

root = pathlib.Path(sys.argv[1])
expected = sys.argv[2]

python_content = (root / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
name_match = re.search(r'^name = "([^"]+)"$', python_content, re.MULTILINE)
version_match = re.search(r'^version = "([^"]+)"$', python_content, re.MULTILINE)
if not name_match or not version_match or (name_match.group(1), version_match.group(1)) != ("keypilot-sdk", expected):
    raise SystemExit("Python package name or version does not match VERSION")

namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
java_root = ET.parse(root / "sdk/java/pom.xml").getroot()
group_id = java_root.findtext("m:groupId", namespaces=namespace)
artifact_id = java_root.findtext("m:artifactId", namespaces=namespace)
version = java_root.findtext("m:version", namespaces=namespace)
if (group_id, artifact_id, version) != ("io.github.agivector", "keypilot-sdk", expected):
    raise SystemExit("Java coordinates or version do not match VERSION")

go_module = (root / "sdk/go/go.mod").read_text(encoding="utf-8").splitlines()[0].strip()
if go_module != "module github.com/agivector/keypilot/sdk/go":
    raise SystemExit("Go module path is invalid")
PY

echo "release metadata verified for $EXPECTED_TAG"

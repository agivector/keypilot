#!/usr/bin/env sh

# Description: Retries Maven build commands after transient dependency repository failures.
# Author: vectorshi
# Created: 2026-11-25

set -eu

attempt=1
maximum_attempts=3
base_delay_seconds="${MAVEN_RETRY_DELAY_SECONDS:-15}"

while [ "$attempt" -le "$maximum_attempts" ]; do
  if mvn "$@"; then
    exit 0
  fi
  if [ "$attempt" -eq "$maximum_attempts" ]; then
    echo "Maven command failed after $maximum_attempts attempts" >&2
    exit 1
  fi
  delay=$((attempt * base_delay_seconds))
  echo "Maven command failed; retrying in ${delay}s (attempt $((attempt + 1))/$maximum_attempts)" >&2
  sleep "$delay"
  attempt=$((attempt + 1))
done

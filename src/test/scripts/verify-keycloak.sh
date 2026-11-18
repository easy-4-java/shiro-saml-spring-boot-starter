#!/usr/bin/env bash
set -euo pipefail

: "${KEYCLOAK_JAVA_HOME:?Set KEYCLOAK_JAVA_HOME to a JDK 21 installation}"
: "${JAVA_HOME:?Set JAVA_HOME to the starter JDK 8 installation}"

version=26.8.2
sha256=dd124787283918bc597628887168333465ee2a811a389e0003569e52be7e487f
scratch=$(mktemp -d "${TMPDIR:-/tmp}/saml-keycloak.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
archive=${KEYCLOAK_ARCHIVE:-"$scratch/keycloak.tar.gz"}
if [[ -z "${KEYCLOAK_ARCHIVE:-}" ]]; then
    curl --fail --location --silent --show-error --retry 2 \
        "https://github.com/keycloak/keycloak/releases/download/$version/keycloak-$version.tar.gz" \
        --output "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | shasum -a 256 -c -
tar -xzf "$archive" -C "$scratch"
export SAML_TEST_KEYCLOAK_HOME="$scratch/keycloak-$version"
cd "$(dirname "$0")/../../.."
mvn -B --no-transfer-progress "$@"

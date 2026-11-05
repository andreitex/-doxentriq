#!/usr/bin/env bash
set -Eeuo pipefail
export KC_DB_PASSWORD="$(cat /run/secrets/mysql-password)"
export KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap-admin
export KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/secrets/bootstrap-password)"
exec /opt/keycloak/bin/kc.sh start --import-realm

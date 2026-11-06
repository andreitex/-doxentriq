#!/usr/bin/env bash
# TEMPLATE: company build-package.py emits this entry plus a pinned worker.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@

company_entry() {
  [[ $# = 2 && $1 = --foundation-only ]] || _il_fail 'full_install_pending_signed_source_and_native_pair'
  _il_root
  local request=$2 package worker expected actual request_sha action operation outcome entry status
  # Protected pre-admission reads use this process's descriptor namespace.
  # install_lock_acquire later binds the same identity to the actual lock.
  IL_OWNER=$BASHPID
  package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  worker="$package/company_install.py"
  expected='@WORKER_SHA256@'
  _il_path "$package"; _il_ancestors "$worker"
  [[ -f "$worker" && ! -L "$worker" && $(stat -c %u -- "$worker") = 0 && $(stat -c %g -- "$worker") = 0 && $(stat -c %h -- "$worker") = 1 ]] || _il_fail untrusted_worker
  [[ $(stat -c %a -- "$worker") = 400 ]] || _il_fail untrusted_worker_mode
  actual=$(sha256sum -- "$worker"); [[ ${actual%% *} = "$expected" ]] || _il_fail worker_hash
  _il_path "$request"; _il_ancestors "$request"; _il_identity "$request" file >/dev/null
  _il_read "$request"; request_sha=$(_il_hash "$IL_TEXT"); request_sha=${request_sha%% *}
  # The namespace itself is the only fresh pre-lock effect, exclusive and fsynced.
  if [[ ! -e /etc/autosoft-install-admission && ! -L /etc/autosoft-install-admission ]]; then
    install_lock_initialize /etc/autosoft-install-admission
  fi
  install_lock_acquire /etc/autosoft-install-admission "$request_sha" 30
  trap 'status=$?; trap - EXIT; if [[ ${IL_ACTIVE:-} = true ]]; then install_lock_release || status=74; fi; exit "$status"' EXIT
  if [[ ! -x /usr/bin/python3 || ! -x /usr/bin/openssl ]]; then
    action=$(_il_hash "prerequisites-v1:$request_sha"); action=${action%% *}
    # Trusted fixed baseline only. Candidate code has not been opened or sourced.
    install_lock_stage "$IL_SESSION" prerequisites "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/timeout --kill-after=15 600 /bin/bash --noprofile --norc -c '
      set -Eeuo pipefail; umask 077
      test -r /etc/os-release; . /etc/os-release
      case "$ID:$VERSION_ID" in
        debian:12|debian:13) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssl ;;
        rocky:9*|rocky:10*) dnf install -y python3 openssl ;;
        *) exit 74 ;;
      esac'
    _il_tool test -x /usr/bin/python3; _il_tool test -x /usr/bin/openssl
    _il_tool /usr/bin/timeout --kill-after=2 10 /usr/bin/python3 -I -B -c 'import sys; assert sys.version_info >= (3,9)'
    _il_tool /usr/bin/timeout --kill-after=2 10 /usr/bin/openssl version >/dev/null
    outcome=$(_il_tool sha256sum -- /usr/bin/python3 /usr/bin/openssl); outcome=$(_il_hash "$outcome"); outcome=${outcome%% *}
    install_lock_confirm_stage "$IL_SESSION" prerequisites "$action" "$outcome"
  fi
  operation=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" --describe --request "$request" --worker-sha "$expected")
  [[ "$operation" =~ ^[a-f0-9]{32}$ ]] || _il_fail invalid_request
  action=$(_il_hash "foundation-v1:$request_sha:$expected"); action=${action%% *}
  local parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$IL_SESSION" "$request_sha" foundation "$action")
  install_lock_stage "$IL_SESSION" foundation "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" --foundation-only --request "$request" --worker-sha "$expected" --parent "${parent[@]}"
  # A separate read-only invocation remeasures actual effects; worker exit0 is not confirmation.
  install_lock_verify "$IL_SESSION" /usr/bin/python3 -I -B "$worker" --verify --request "$request" --worker-sha "$expected" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/verified"
  outcome=${IL_TEXT#*$'\n'outcome=}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$IL_TEXT" = $'foundation-verified-v1\noperation='"$operation"$'\noutcome='"$outcome"$'\n' ]] || _il_fail independent_verification_record
  install_lock_confirm_stage "$IL_SESSION" foundation "$action" "$outcome"
  install_lock_complete "$IL_SESSION" "$outcome"
  printf 'Foundation effects independently confirmed. Full platform installation is pending.\n'
}
company_entry "$@"

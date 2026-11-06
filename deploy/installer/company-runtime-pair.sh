#!/usr/bin/env bash
# Independently delivered company prerequisite; starts no application services.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@

company_runtime_pair_entry() {
  [[ $# = 2 && $1 = --initialize-runtime-pair ]] || _il_fail runtime_pair_only_required
  _il_root
  local request=$2 package worker expected actual request_sha operation action marker outcome status nofile
  IL_OWNER=$BASHPID
  nofile=$(ulimit -Sn)
  if [[ "$nofile" != unlimited ]]; then
    [[ "$nofile" =~ ^[0-9]+$ ]] || _il_fail invalid_nofile_limit
    if (( nofile < 16384 )); then ulimit -Sn 16384 || _il_fail nofile_16384_required; fi
  fi
  package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  worker="$package/company-native-retention.py"
  expected='@WORKER_SHA256@'
  _il_path "$package"; _il_ancestors "$worker"
  [[ -f "$worker" && ! -L "$worker" && $(stat -c %u -- "$worker") = 0 && $(stat -c %g -- "$worker") = 0 && $(stat -c %h -- "$worker") = 1 && $(stat -c %a -- "$worker") = 400 ]] || _il_fail untrusted_runtime_pair_worker
  actual=$(sha256sum -- "$worker"); [[ ${actual%% *} = "$expected" ]] || _il_fail runtime_pair_worker_hash
  [[ "$request" =~ ^/opt/autosoft-company/requests/([a-f0-9]{32})\.json$ ]] || _il_fail runtime_pair_request_path
  operation=${BASH_REMATCH[1]}; [[ "$operation" != 00000000000000000000000000000000 ]] || _il_fail runtime_pair_operation
  _il_path "$request"; _il_ancestors "$request"; _il_identity "$request" file >/dev/null
  _il_read "$request"; request_sha=$(_il_hash "$IL_TEXT"); request_sha=${request_sha%% *}
  [[ -d /etc/autosoft-install-admission && ! -L /etc/autosoft-install-admission ]] || _il_fail verified_foundation_required
  # Effect-free source/storage/host admission precedes a durable session. The
  # execute child repeats it under the real lock and exact action binding.
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" runtime-pair-action --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail runtime_pair_action
  install_lock_acquire /etc/autosoft-install-admission "$request_sha" 30
  trap 'status=$?; trap - EXIT; if [[ ${IL_ACTIVE:-} = true ]]; then install_lock_release || status=74; fi; exit "$status"' EXIT
  local parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$IL_SESSION" "$request_sha" fresh-runtime-pair "$action")
  if ! install_lock_stage "$IL_SESSION" fresh-runtime-pair "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" initialize-runtime-pair --request "$request" --parent "${parent[@]}"; then
    _il_fail runtime_pair_child_failed_preserve_evidence
  fi
  install_lock_verify "$IL_SESSION" /usr/bin/python3 -I -B "$worker" verify-runtime-pair --request "$request" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/fresh-runtime-pair/confirmation"
  marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = $'runtime-pair-verified-v1\nrequest='"$request_sha"$'\nsession='"$IL_SESSION"$'\nstage=fresh-runtime-pair\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail runtime_pair_confirmation_binding
  install_lock_confirm_stage "$IL_SESSION" fresh-runtime-pair "$action" "$outcome"
  install_lock_complete "$IL_SESSION" "$outcome"
  printf 'Runtime admission and quota pair independently confirmed. Rendering, identity and service activation remain incomplete.\n'
}
company_runtime_pair_entry "$@"

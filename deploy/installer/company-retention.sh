#!/usr/bin/env bash
# Company package template. Retains signed source only; no platform activation.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@

company_retention_entry() {
  [[ $# = 2 && $1 = --retention-only ]] || _il_fail retention_only_required
  _il_root
  local request=$2 package worker expected actual request_sha operation stage action outcome verification status
  local store_outcome='' final_outcome='' marker='' session='' nofile=''
  # _il_read's held-descriptor check needs this Bash identity even before lock
  # acquisition. It is not a live-lock assertion and sets no IL_ACTIVE flag.
  IL_OWNER=$BASHPID
  nofile=$(ulimit -Sn)
  if [[ "$nofile" != unlimited ]]; then
    [[ "$nofile" =~ ^[0-9]+$ ]] || _il_fail invalid_nofile_limit
    if (( nofile < 4096 )); then ulimit -Sn 4096 || _il_fail nofile_4096_required; fi
  fi
  package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  worker="$package/company-native-retention.py"
  expected='@WORKER_SHA256@'
  _il_path "$package"; _il_ancestors "$worker"
  [[ -f "$worker" && ! -L "$worker" && $(stat -c %u -- "$worker") = 0 && $(stat -c %g -- "$worker") = 0 && $(stat -c %h -- "$worker") = 1 && $(stat -c %a -- "$worker") = 400 ]] || _il_fail untrusted_retention_worker
  actual=$(sha256sum -- "$worker"); [[ ${actual%% *} = "$expected" ]] || _il_fail retention_worker_hash
  [[ "$request" =~ ^/opt/autosoft-company/requests/([a-f0-9]{32})\.json$ ]] || _il_fail retention_request_path
  operation=${BASH_REMATCH[1]}; [[ "$operation" != 00000000000000000000000000000000 ]] || _il_fail retention_operation
  _il_path "$request"; _il_ancestors "$request"; _il_identity "$request" file >/dev/null
  _il_read "$request"; request_sha=$(_il_hash "$IL_TEXT"); request_sha=${request_sha%% *}
  [[ -d /etc/autosoft-install-admission && ! -L /etc/autosoft-install-admission ]] || _il_fail verified_foundation_required
  install_lock_acquire /etc/autosoft-install-admission "$request_sha" 30
  trap 'status=$?; trap - EXIT; if [[ ${IL_ACTIVE:-} = true ]]; then install_lock_release || status=74; fi; exit "$status"' EXIT
  session=$IL_SESSION
  for stage in company-platform-store company-source-materialize; do
    # Plan owns no external action. Its signed-source/native readback closes
    # before it exclusively persists the original plan and returns the action.
    action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" plan-stage --request "$request" --stage "$stage" --persist)
    [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail invalid_retention_plan
    local parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" "$stage" "$action")
    # This synchronous return is the parent's observation of child exit.
    # Failure after emitting/writing a record is still failure: no confirmation.
    if ! install_lock_stage "$session" "$stage" "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" execute-verify --request "$request" --stage "$stage" --persist --parent "${parent[@]}"; then
      _il_fail retention_child_failed_preserve_evidence
    fi
    # Separate read-only record inspection rechecks the same live parent and
    # exact closed records; only its small bound marker is interpreted by Bash.
    install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" inspect-completion --request "$request" --stage "$stage" --parent "${parent[@]}"
    _il_read "/opt/autosoft-company/evidence/$operation/$stage/confirmation"
    marker=$IL_TEXT
    outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
    verification=${marker#*$'\nverification='}; verification=${verification%%$'\n'*}
    [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$verification" =~ ^[a-f0-9]{64}$ ]] || _il_fail retention_confirmation_shape
    [[ "$marker" = $'retention-verified-v1\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage='"$stage"$'\naction='"$action"$'\noutcome='"$outcome"$'\nverification='"$verification"$'\n' ]] || _il_fail retention_confirmation_binding
    install_lock_confirm_stage "$session" "$stage" "$action" "$outcome"
    if [[ "$stage" = company-platform-store ]]; then store_outcome=$outcome; fi
  done
  final_outcome=$(_il_hash "retention-only-v1:$request_sha:$store_outcome:$outcome"); final_outcome=${final_outcome%% *}
  # Completes this two-stage admission session, not the full installation.
  install_lock_complete "$session" "$final_outcome"
  printf 'Signed source retention and materialization independently confirmed. Full platform installation is pending.\n'
}
company_retention_entry "$@"

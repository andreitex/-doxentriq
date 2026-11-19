#!/usr/bin/env bash
# Store -> Source -> startup -> render -> private infrastructure -> identity, one live parent.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@

_ci_inventory() {
  local directory="$IL_BASE/sessions/$IL_SESSION" entry name label action outcome expected gap=false pending=false allowed=false
  CI_OUTCOMES=(); CI_CONFIRMED_ACTIONS=(); CI_PENDING=''; CI_ACTION=''
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    name=${entry##*/}; allowed=false
    [[ "$name" != intent ]] || allowed=true
    for label in "${CI_STAGES[@]}"; do
      [[ "$name" != "$label.intent" && "$name" != "$label.confirmed" ]] || allowed=true
    done
    [[ "$allowed" = true ]] || _il_fail private_recovery_unexpected_record_preserved
    _il_identity "$entry" file >/dev/null
  done
  for label in "${CI_STAGES[@]}"; do
    if [[ ! -e "$directory/$label.intent" ]]; then
      [[ ! -e "$directory/$label.confirmed" ]] || _il_fail private_recovery_orphan_confirmation
      gap=true; continue
    fi
    [[ "$gap" = false && "$pending" = false ]] || _il_fail private_recovery_stage_order
    _il_read "$directory/$label.intent"; action=${IL_TEXT#*$'\naction='}; action=${action%%$'\n'*}
    [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail private_recovery_action
    _il_stage_intent "$IL_SESSION" "$label" "$action"
    if [[ ! -e "$directory/$label.confirmed" ]]; then
      CI_PENDING=$label; CI_ACTION=$action; pending=true; continue
    fi
    _il_read "$directory/$label.confirmed"; outcome=${IL_TEXT#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
    [[ "$outcome" =~ ^[a-f0-9]{64}$ ]] || _il_fail private_recovery_outcome
    printf -v expected 'install-stage-confirmed-v1\nsession=%s\nstage=%s\naction=%s\noutcome=%s\nindependently_confirmed=true\n' "$IL_SESSION" "$label" "$action" "$outcome"
    [[ "$IL_TEXT" = "$expected" ]] || _il_fail private_recovery_confirmation_binding
    CI_OUTCOMES+=("$outcome")
    CI_CONFIRMED_ACTIONS+=("$action")
  done
}

_ci_previous() {
  CI_CURRENT=$1
  local index=0 label
  for label in "${CI_STAGES[@]}"; do
    ((index+=1))
    if [[ "$label" = "$1" ]]; then
      if (( index <= ${#CI_OUTCOMES[@]} )); then
        outcome=${CI_OUTCOMES[index-1]}
        CI_RETAINED_ACTION=${CI_CONFIRMED_ACTIONS[index-1]}
        printf '[%s/%s] %s: prior confirmation retained.\n' "$index" "${#CI_STAGES[@]}" "$label"
        return 0
      fi
      return 1
    fi
  done
  _il_fail unexpected_private_stage
}

_ci_step() {
  local stage=$1 action_command=$2 execute_command=$3 verify_command=$4 magic=$5
  CI_CURRENT=$stage
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" "$action_command" --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail private_stage_action
  if _ci_previous "$stage"; then
    [[ "$action" = "$CI_RETAINED_ACTION" ]] || _il_fail private_recovery_worker_changed
    return
  fi
  parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" "$stage" "$action")
  if [[ "$CI_PENDING" = "$stage" ]]; then
    [[ "$action" = "$CI_ACTION" ]] || _il_fail private_recovery_worker_changed
    [[ ! -e "/opt/autosoft-company/evidence/$operation/$stage/verified.json" && ! -L "/opt/autosoft-company/evidence/$operation/$stage/verified.json" && ! -e "/opt/autosoft-company/evidence/$operation/$stage/confirmation" && ! -L "/opt/autosoft-company/evidence/$operation/$stage/confirmation" ]] || _il_fail partial_private_verification_preserved_IT_recovery_required
    printf '%s: independently checking recorded execution; mutation will not be repeated.\n' "$stage"
  else
    printf '%s: applying the verified private installation step.\n' "$stage"
    if ! install_lock_stage "$session" "$stage" "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" "$execute_command" --request "$request" --parent "${parent[@]}"; then
      _il_fail private_stage_uncertain_preserve_records_do_not_retry
    fi
  fi
  install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" "$verify_command" --request "$request" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/$stage/confirmation"
  marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = "$magic"$'\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage='"$stage"$'\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail private_stage_confirmation_binding
  install_lock_confirm_stage "$session" "$stage" "$action" "$outcome"
}

company_initialize_entry() {
  if [[ $# = 1 && $1 = --help ]]; then
    printf '%s\n' 'Continue a verified foundation through private services and identity.' \
      'Usage: --retain-render-and-initialize-private REQUEST' \
      'Recovery: --recover-private-initialization REQUEST SESSION' \
      'Use the original protected request and package. Recorded mutations are never replayed.' \
      'Partial identity helper or verification records require IT inspection; keep all evidence and data.' \
      'Public startup and complete installation acceptance remain pending.'
    return
  fi
  [[ ( $# = 2 && $1 = --retain-render-and-initialize-private ) || ( $# = 3 && $1 = --recover-private-initialization ) ]] || _il_fail continuation_arguments
  local mode=$1 recovering=${3:-}
  CI_CURRENT='preflight'
  CI_STAGES=(company-platform-store company-source-materialize company-stored-startup company-render company-private-infrastructure company-initial-identity)
  _il_root
  local request=$2 package worker expected actual request_sha operation stage action outcome verification status
  local store_outcome='' final_outcome='' marker='' session='' nofile='' source_outcome=''
  local parent=()
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
  [[ -f "$worker" && ! -L "$worker" && $(stat -c %u -- "$worker") = 0 && $(stat -c %g -- "$worker") = 0 && $(stat -c %h -- "$worker") = 1 && $(stat -c %a -- "$worker") = 400 ]] || _il_fail untrusted_continuation_worker
  actual=$(sha256sum -- "$worker"); [[ ${actual%% *} = "$expected" ]] || _il_fail continuation_worker_hash
  [[ "$request" =~ ^/opt/autosoft-company/requests/([a-f0-9]{32})\.json$ ]] || _il_fail continuation_request_path
  operation=${BASH_REMATCH[1]}; [[ "$operation" != 00000000000000000000000000000000 ]] || _il_fail continuation_operation
  _il_path "$request"; _il_ancestors "$request"; _il_identity "$request" file >/dev/null
  _il_read "$request"; request_sha=$(_il_hash "$IL_TEXT"); request_sha=${request_sha%% *}
  [[ -d /etc/autosoft-install-admission && ! -L /etc/autosoft-install-admission ]] || _il_fail verified_foundation_required
  if [[ "$mode" = --recover-private-initialization ]]; then
    install_lock_recover /etc/autosoft-install-admission "$request_sha" 30 "$recovering"
  else
    _il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" continuation-ready --request "$request"
    _il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" render-ready --request "$request"
    _il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" infrastructure-ready --request "$request"
    install_lock_acquire /etc/autosoft-install-admission "$request_sha" 30
  fi
  trap 'status=$?; trap - EXIT; if [[ $status != 0 && ${IL_ACTIVE:-} = true ]]; then printf "Private installation stopped at %s. Session: %s. Keep records and storage. Explicit recovery uses this same request/session; incomplete identity helper or verification evidence requires IT inspection.\n" "${CI_CURRENT:-preflight}" "${IL_SESSION:-unavailable}" >&2; fi; if [[ ${IL_ACTIVE:-} = true ]]; then install_lock_release || status=74; fi; exit "$status"' EXIT
  session=$IL_SESSION
  local binding_path="/opt/autosoft-company/evidence/$operation/private-session" binding_text
  _il_ancestors "$binding_path"; _il_identity "${binding_path%/*}" directory >/dev/null
  printf -v binding_text 'private-continuation-session-v1\nrequest=%s\nsession=%s\nworker=%s\nstages=%s\n' "$request_sha" "$session" "$expected" "${#CI_STAGES[@]}"
  if [[ "$mode" = --recover-private-initialization ]]; then
    _il_read "$binding_path"; [[ "$IL_TEXT" = "$binding_text" ]] || _il_fail original_private_package_required
  else
    _il_write "$binding_path" "$binding_text"
  fi
  _ci_inventory
  # Producer copies the exact existing retention-only stage loop, not its
  # session completion. Both outcomes stay in this SAME live parent session.
# @EMBED_RETENTION_STAGE_LOOP@
  source_outcome=$outcome
  _ci_step company-stored-startup startup-action inspect-stored-startup verify-stored-startup stored-startup-verified-v1
  local startup_outcome=$outcome
  _ci_step company-render render-action render-configuration verify-render render-verified-v1
  local render_outcome=$outcome
  _ci_step company-private-infrastructure infrastructure-action initialize-private-infrastructure verify-private-infrastructure private-infrastructure-verified-v1
  local infrastructure_outcome=$outcome
  printf 'Private services confirmed. Provisioning the initial identity policy.\n'
  _ci_step company-initial-identity identity-action provision-initial-identity verify-initial-identity initial-identity-verified-v1
  final_outcome=$(_il_hash "private-initialization-only-v1:$request_sha:$store_outcome:$source_outcome:$startup_outcome:$render_outcome:$infrastructure_outcome:$outcome"); final_outcome=${final_outcome%% *}
  install_lock_complete "$session" "$final_outcome"
  printf 'Private infrastructure and initial identity policy independently verified. Public startup, browser MFA, backups and reboot recovery remain pending.\n'
}
company_initialize_entry "$@"

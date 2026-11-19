#!/usr/bin/env bash
# Configure -> seed Git -> initialize runtime admission, one genuine parent.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@

_cp_inventory() {
  local expected_configuration_action=${1:?current packaged configuration action required}
  local directory="$IL_BASE/sessions/$IL_SESSION" entry name label action outcome expected gap=false pending=false
  CP_CONFIRMED=(); CP_PENDING=''; CP_ACTION=''
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    name=${entry##*/}
    case "$name" in
      intent|company-configuration.intent|company-configuration.confirmed|repository-seed.intent|repository-seed.confirmed|fresh-runtime-pair.intent|fresh-runtime-pair.confirmed) ;;
      *) _il_fail preparation_unexpected_record_preserved ;;
    esac
    _il_identity "$entry" file >/dev/null
  done
  for label in company-configuration repository-seed fresh-runtime-pair; do
    if [[ ! -e "$directory/$label.intent" ]]; then
      [[ ! -e "$directory/$label.confirmed" ]] || _il_fail preparation_orphan_confirmation
      gap=true; continue
    fi
    [[ "$gap" = false && "$pending" = false ]] || _il_fail preparation_stage_order
    _il_read "$directory/$label.intent"; action=${IL_TEXT#*$'\naction='}; action=${action%%$'\n'*}
    [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail preparation_stage_action
    if [[ "$label" = company-configuration ]]; then
      [[ "$action" = "$expected_configuration_action" ]] || _il_fail preparation_worker_changed
    fi
    _il_stage_intent "$IL_SESSION" "$label" "$action"
    if [[ ! -e "$directory/$label.confirmed" ]]; then
      CP_PENDING=$label; CP_ACTION=$action; pending=true; continue
    fi
    _il_read "$directory/$label.confirmed"; outcome=${IL_TEXT#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
    [[ "$outcome" =~ ^[a-f0-9]{64}$ ]] || _il_fail preparation_stage_outcome
    printf -v expected 'install-stage-confirmed-v1\nsession=%s\nstage=%s\naction=%s\noutcome=%s\nindependently_confirmed=true\n' "$IL_SESSION" "$label" "$action" "$outcome"
    [[ "$IL_TEXT" = "$expected" ]] || _il_fail preparation_confirmation_binding
    CP_CONFIRMED+=("$outcome")
  done
}

company_prepare_entry() {
  if [[ $# = 1 && $1 = --help ]]; then
    printf '%s\n' 'Prepare a verified foundation using the protected configuration questionnaire, Git seed and runtime admission.' \
      'Usage: company-prepare.sh --prepare-foundation REQUEST' \
      'Recovery: company-prepare.sh --recover-preparation REQUEST SESSION' \
      'Recovery rechecks recorded effects; it never repeats the interrupted mutation. Keep all records and storage.' \
      'This command does not start applications or finish installation.'
    return
  fi
  [[ ( $# = 2 && $1 = --prepare-foundation ) || ( $# = 3 && $1 = --recover-preparation ) ]] || _il_fail preparation_arguments
  _il_root
  local mode=$1 request=$2 recovering=${3:-} package worker expected actual request_sha operation nofile status
  local stage action_command execute_command verify_command magic action outcome marker index=0 final_outcome
  CP_CURRENT='preflight'
  IL_OWNER=$BASHPID
  nofile=$(ulimit -Sn)
  if [[ "$nofile" != unlimited ]]; then
    [[ "$nofile" =~ ^[0-9]+$ ]] || _il_fail invalid_nofile_limit
    if (( nofile < 16384 )); then ulimit -Sn 16384 || _il_fail nofile_16384_required; fi
  fi
  package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  worker="$package/company-native-retention.py"; expected='@WORKER_SHA256@'
  _il_path "$package"; _il_ancestors "$worker"
  [[ -f "$worker" && ! -L "$worker" && $(stat -c %u -- "$worker") = 0 && $(stat -c %g -- "$worker") = 0 && $(stat -c %h -- "$worker") = 1 && $(stat -c %a -- "$worker") = 400 ]] || _il_fail untrusted_preparation_worker
  actual=$(sha256sum -- "$worker"); [[ ${actual%% *} = "$expected" ]] || _il_fail preparation_worker_hash
  [[ "$request" =~ ^/opt/autosoft-company/requests/([a-f0-9]{32})\.json$ ]] || _il_fail preparation_request_path
  operation=${BASH_REMATCH[1]}; [[ "$operation" != 00000000000000000000000000000000 ]] || _il_fail preparation_operation
  _il_path "$request"; _il_ancestors "$request"; _il_identity "$request" file >/dev/null
  _il_read "$request"; request_sha=$(_il_hash "$IL_TEXT"); request_sha=${request_sha%% *}
  [[ -d /etc/autosoft-install-admission && ! -L /etc/autosoft-install-admission ]] || _il_fail verified_foundation_required
  # Catalog qualification is effect free; each worker additionally reauthenticates
  # source, storage and the exact current action under the live parent.
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" configuration-action --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail configuration_action
  if [[ "$mode" = --recover-preparation ]]; then
    install_lock_recover /etc/autosoft-install-admission "$request_sha" 30 "$recovering"
  else
    install_lock_acquire /etc/autosoft-install-admission "$request_sha" 30
  fi
  trap 'status=$?; trap - EXIT; if [[ $status != 0 && ${IL_ACTIVE:-} = true ]]; then printf "Preparation stopped at %s. Session: %s. Keep records and storage. Use explicit recovery with this request/session; an unresolved write must be inspected by IT.\n" "${CP_CURRENT:-preflight}" "${IL_SESSION:-unavailable}" >&2; fi; if [[ ${IL_ACTIVE:-} = true ]]; then install_lock_release || status=74; fi; exit "$status"' EXIT
  _cp_inventory "$action"
  local session=$IL_SESSION parent=() outcomes=("${CP_CONFIRMED[@]}")
  for stage in company-configuration repository-seed fresh-runtime-pair; do
    ((index+=1)); CP_CURRENT=$stage
    if (( index <= ${#CP_CONFIRMED[@]} )); then
      printf '[%s/3] %s: prior confirmation retained.\n' "$index" "$stage"
      continue
    fi
    case "$stage" in
      company-configuration) action_command=configuration-action; execute_command=configure-foundation; verify_command=verify-configuration; magic=configuration-verified-v1 ;;
      repository-seed) action_command=repository-action; execute_command=seed-repository; verify_command=verify-repository; magic=repository-verified-v1 ;;
      fresh-runtime-pair) action_command=runtime-pair-action; execute_command=initialize-runtime-pair; verify_command=verify-runtime-pair; magic=runtime-pair-verified-v1 ;;
    esac
    if [[ "$CP_PENDING" = "$stage" ]]; then
      action=$CP_ACTION
      printf '[%s/3] %s: independently rechecking the interrupted stage; no mutation replay.\n' "$index" "$stage"
    else
      action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" "$action_command" --request "$request")
      [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail preparation_action
      parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" "$stage" "$action")
      printf '[%s/3] %s: applying the verified preparation step.\n' "$index" "$stage"
      if ! install_lock_stage "$session" "$stage" "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" "$execute_command" --request "$request" --parent "${parent[@]}"; then
        _il_fail preparation_child_failed_preserve_evidence
      fi
    fi
    parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" "$stage" "$action")
    install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" "$verify_command" --request "$request" --parent "${parent[@]}"
    _il_read "/opt/autosoft-company/evidence/$operation/$stage/confirmation"
    marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
    [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = "$magic"$'\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage='"$stage"$'\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail preparation_confirmation_binding
    install_lock_confirm_stage "$session" "$stage" "$action" "$outcome"
    outcomes+=("$outcome")
    printf '[%s/3] %s: independently confirmed.\n' "$index" "$stage"
  done
  (( ${#outcomes[@]} == 3 )) || _il_fail preparation_outcomes
  final_outcome=$(_il_hash "preparation-only-v1:$request_sha:${outcomes[0]}:${outcomes[1]}:${outcomes[2]}"); final_outcome=${final_outcome%% *}
  install_lock_complete "$session" "$final_outcome"
  printf 'Foundation preparation complete. Signed-source retention, rendering, identity, public startup and recovery acceptance still remain.\n'
}
company_prepare_entry "$@"

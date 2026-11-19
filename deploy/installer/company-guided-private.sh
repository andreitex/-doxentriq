#!/usr/bin/env bash
# Company-produced fresh private setup. Each child retains its original admission.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@
GP_PACKAGE_SHA='@GUIDED_PACKAGE_SHA256@'
GP_INTAKE_AVAILABLE='@REQUEST_INTAKE_AVAILABLE@'

_gp_file() {
  local path="$GP_PACKAGE/$1" expected=$2 size=$3 before after digest
  _il_path "$path"; _il_ancestors "$path"
  [[ -f "$path" && ! -L "$path" ]] || _il_fail guided_package_file_required
  before=$(_il_metadata "$path")
  [[ $(stat -c '%u:%g:%a:%h:%s' -- "$path") = "0:0:400:1:$size" ]] || _il_fail guided_package_profile
  digest=$(sha256sum -- "$path"); after=$(_il_metadata "$path")
  [[ "$before" = "$after" && ${digest%% *} = "$expected" ]] || _il_fail guided_package_changed
  if [[ $1 = company_install.py ]]; then GP_FOUNDATION_WORKER_SHA=$expected; fi
}

_gp_package() {
# @GUIDED_PACKAGE_FILES@
}

_gp_receipt() {
  # A delivered receipt is immutable package data (0400), not an admission record (0600).
  local path="$GP_PACKAGE/guided-delivery.txt" before after body='' status size
  local dev ino bits uid gid mode links modified changed
  [[ -z ${IL_RECORD_FD:-} ]] || _il_fail nested_record_read
  _il_path "$path"; _il_ancestors "$path"
  [[ -f "$path" && ! -L "$path" ]] || _il_fail intake_receipt_file_required
  before=$(_il_metadata "$path")
  IFS=: read -r dev ino bits uid gid mode links size modified changed <<< "$before"
  [[ "$uid:$gid:$mode:$links" = 0:0:400:1 && "$size" -gt 0 && "$size" -le 4096 ]] || _il_fail intake_receipt_profile
  exec {IL_RECORD_FD}<"$path" || _il_fail record_open_unavailable
  [[ $(_il_fd_identity "$IL_RECORD_FD" file) = "$before" ]] || _il_fail record_replaced
  if IFS= read -r -d '' -n 4097 body <&"$IL_RECORD_FD"; then status=0; else status=$?; fi
  [[ "$status" = 1 && ${#body} = "$size" ]] || _il_fail malformed_record
  after=$(_il_metadata "$path")
  [[ -f "$path" && ! -L "$path" && "$before" = "$after" && $(_il_fd_identity "$IL_RECORD_FD" file) = "$before" ]] || _il_fail record_replaced
  exec {IL_RECORD_FD}<&- || _il_fail record_close_unavailable
  unset IL_RECORD_FD
  GP_RECEIPT=$body
}

_gp_delivery() {
  local expected=$1 body actual line name digest size total=0 pattern
  local names=(company-guided-private.sh company-install.sh company-native-retention.py company-prepare.sh company-private-quota.sh company-request-intake.py company-signing-public-key.pem company_install.py guided-request-defaults.json installation-status.py)
  [[ "$GP_INTAKE_AVAILABLE" = true && "$GP_PACKAGE" = /opt/autosoft-company/bootstrap ]] || _il_fail 'Request intake needs a company-delivered intake package in /opt/autosoft-company/bootstrap.'
  [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || _il_fail 'Provide the delivery receipt SHA256 received through the independent company channel.'
  _gp_receipt; body=$GP_RECEIPT
  (( ${#body} <= 4096 )) || _il_fail intake_delivery_receipt_size
  actual=$(_il_hash "$body"); actual=${actual%% *}
  [[ "$actual" = "$expected" && "$body" = $'company-guided-delivery-v1\n'* ]] || _il_fail 'Delivery receipt differs from the independently supplied digest.'
  body=${body#*$'\n'}
  for name in "${names[@]}"; do
    [[ "$body" = *$'\n'* ]] || _il_fail intake_delivery_receipt_incomplete
    line=${body%%$'\n'*}; body=${body#*$'\n'}
    pattern="^${name//./\\.} "'([a-f0-9]{64}) ([1-9][0-9]{0,6})$'
    [[ "$line" =~ $pattern ]] || _il_fail intake_delivery_receipt_member
    digest=${BASH_REMATCH[1]}; size=${BASH_REMATCH[2]}
    ((total+=size)); ((total<=4194304)) || _il_fail intake_delivery_package_size
    _gp_file "$name" "$digest" "$size"
  done
  [[ -z "$body" ]] || _il_fail intake_delivery_receipt_extra_content
}

_gp_request() {
  local path=$1 mode=$2 value pattern part component
  local components=()
  _il_path "$path"; _il_ancestors "$path"; _il_read "$path"; value=$IL_TEXT
  # Canonical data only; original children independently validate every request.
  pattern='^\{"backingFile":"([^"\\]+)","bundleRoot":"([^"\\]+)","capacityGiB":([1-9][0-9]{1,3}),"dataDir":"([^"\\]+)","keyPath":"([^"\\]+)","mode":"(foundation-only|full-installation)","operationId":"([a-f0-9]{32})","releaseSha256":"([a-f0-9]{64})","runscSha512":"([a-f0-9]{128})","runscVersion":"([0-9]{8}\.[0-9]{1,8})","schemaVersion":1,"sourceRoot":"([^"\\]+)"\}'$'\n''$'
  [[ "$value" =~ $pattern ]] || _il_fail guided_canonical_request_required
  GP_VALUES=("${BASH_REMATCH[@]:1}")
  [[ ${GP_VALUES[5]} = "$mode" && ${GP_VALUES[6]} != 00000000000000000000000000000000 ]] || _il_fail guided_request_mode_operation
  (( GP_VALUES[2] >= 32 && GP_VALUES[2] <= 4096 )) || _il_fail guided_capacity
  for part in 0 1 3 4 10; do
    (( ${#GP_VALUES[part]} <= 1024 )) || _il_fail guided_path_length
    _il_path "${GP_VALUES[part]}"
    IFS=/ read -r -a components <<< "${GP_VALUES[part]}"
    (( ${#components[@]} <= 32 )) || _il_fail guided_path_depth
    for component in "${components[@]}"; do
      (( ${#component} <= 255 )) || _il_fail guided_path_component
    done
  done
  local backing=${GP_VALUES[0]} bundle=${GP_VALUES[1]} data=${GP_VALUES[3]} key=${GP_VALUES[4]} source=${GP_VALUES[10]}
  [[ "$data" = /srv/* && "$data" != /srv/autosoft-company && "$data" != /srv/autosoft-company/* && "$backing" != "$data" && "$backing" != "$data/"* && "$data" != "$backing/"* ]] || _il_fail guided_storage_paths
  [[ "$backing" != /opt/autosoft-company && "$backing" != /opt/autosoft-company/* && /opt/autosoft-company != "$backing/"* ]] || _il_fail guided_storage_ancestry
  [[ "$bundle" = /opt/autosoft-company/incoming/* && "$source" = /opt/autosoft-company/incoming/* && "$key" = /opt/autosoft-company/bootstrap/*.pem ]] || _il_fail guided_release_paths
  GP_REQUEST_RAW=$value
  GP_REQUEST_SHA=$(_il_hash "$value"); GP_REQUEST_SHA=${GP_REQUEST_SHA%% *}
}

_gp_pair() {
  local index
  _gp_request "$GP_FOUNDATION" foundation-only
  GP_FOUNDATION_SHA=$GP_REQUEST_SHA; GP_FOUNDATION_RAW=$GP_REQUEST_RAW; GP_SHARED=("${GP_VALUES[@]}")
  _gp_request "$GP_FULL" full-installation
  GP_FULL_SHA=$GP_REQUEST_SHA; GP_FULL_RAW=$GP_REQUEST_RAW; GP_OPERATION=${GP_VALUES[6]}
  [[ "$GP_FOUNDATION" != "$GP_FULL" && "$GP_FULL" = "/opt/autosoft-company/requests/$GP_OPERATION.json" ]] || _il_fail guided_distinct_request_paths
  for index in 0 2 3 4 6 8 9; do
    [[ ${GP_SHARED[index]} = "${GP_VALUES[index]}" ]] || _il_fail guided_foundation_full_binding
  done
}

_gp_recheck() {
  _gp_package
  _il_read "$GP_FOUNDATION"; [[ "$IL_TEXT" = "$GP_FOUNDATION_RAW" ]] || _il_fail guided_foundation_request_changed
  _il_read "$GP_FULL"; [[ "$IL_TEXT" = "$GP_FULL_RAW" ]] || _il_fail guided_full_request_changed
}

_gp_prior_session() {
  local directory count=0
  [[ -e /etc/autosoft-install-admission || -L /etc/autosoft-install-admission ]] || return 1
  IL_BASE=/etc/autosoft-install-admission; _il_context
  for directory in "$IL_BASE/sessions"/* "$IL_BASE/sessions"/.[!.]* "$IL_BASE/sessions"/..?*; do
    [[ -e "$directory" || -L "$directory" ]] || continue
    ((count+=1)); ((count<=1024)) || _il_fail guided_session_limit
    _il_session_intent "$directory" "${directory##*/}"
    if [[ "$IL_FOUND_REQUEST" = "$GP_FULL_SHA" || "$IL_FOUND_REQUEST" = "$GP_FOUNDATION_SHA" ]]; then return 0; fi
  done
  return 1
}

_gp_status() (
  # Advisory only. Never turn a status observation into continuation authority.
  IL_OWNER=$BASHPID
  _gp_package
  printf '%s\n' 'Private setup is incomplete. Keep the original package, requests, records and storage.'
  if [[ -x /usr/bin/python3 ]]; then
    /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$GP_PACKAGE/installation-status.py" || true
  else
    printf '%s\n' 'Read-only installation status needs Python 3; ask IT to inspect the retained foundation evidence.'
  fi
  [[ -d /etc/autosoft-install-admission && ! -L /etc/autosoft-install-admission ]] || exit 0
  IL_BASE=/etc/autosoft-install-admission
  _il_context
  local directory session count=0 full_sessions=0 foundation_sessions=0
  local evidence="/opt/autosoft-company/evidence/$GP_OPERATION" child preparation_seen=false later_seen=false private_session='' private_pattern
  for directory in "$IL_BASE/sessions"/* "$IL_BASE/sessions"/.[!.]* "$IL_BASE/sessions"/..?*; do
    [[ -e "$directory" || -L "$directory" ]] || continue
    ((count+=1)); ((count<=1024)) || _il_fail guided_status_session_limit
    _il_session_intent "$directory" "${directory##*/}"
    if [[ "$IL_FOUND_REQUEST" = "$GP_FULL_SHA" ]]; then ((full_sessions+=1)); fi
    if [[ "$IL_FOUND_REQUEST" = "$GP_FOUNDATION_SHA" ]]; then ((foundation_sessions+=1)); fi
  done
  count=0
  for child in "$evidence"/* "$evidence"/.[!.]* "$evidence"/..?*; do
    [[ -e "$child" || -L "$child" ]] || continue
    ((count+=1)); ((count<=32)) || _il_fail guided_status_evidence_limit
    case "${child##*/}" in
      intent.json|result.json|verified) ;;
      company-configuration|repository-seed|fresh-runtime-pair) preparation_seen=true ;;
      *) later_seen=true ;;
    esac
  done
  if [[ -f "$evidence/private-session" && ! -L "$evidence/private-session" ]]; then
    _il_read "$evidence/private-session"
    private_pattern=$'private-continuation-session-v1\nrequest='"$GP_FULL_SHA"$'\nsession=(s-[A-Za-z0-9]{12})\nworker=[a-f0-9]{64}\nstages=7\n'
    if [[ "$IL_TEXT" =~ ^$private_pattern$ ]]; then private_session=${BASH_REMATCH[1]}; fi
  fi
  count=0
  for directory in "$IL_BASE/sessions"/* "$IL_BASE/sessions"/.[!.]* "$IL_BASE/sessions"/..?*; do
    [[ -e "$directory" || -L "$directory" ]] || continue
    ((count+=1)); ((count<=1024)) || _il_fail guided_status_session_limit
    session=${directory##*/}; _il_session_intent "$directory" "$session"
    [[ "$IL_FOUND_REQUEST" = "$GP_FULL_SHA" || "$IL_FOUND_REQUEST" = "$GP_FOUNDATION_SHA" ]] || continue
    if [[ -e "$directory/complete" || -L "$directory/complete" ]]; then
      if [[ -e "$directory/fresh-runtime-pair.confirmed" && "$full_sessions" = 1 && "$later_seen" = false ]]; then
        printf 'Preparation session %s completed. To verify it and continue private setup:\n  bash --noprofile --norc %s/company-guided-private.sh --continue-after-preparation %s %s %s\n' "$session" "$GP_PACKAGE" "$GP_FOUNDATION" "$GP_FULL" "$session"
      elif [[ -e "$directory/foundation.confirmed" && "$full_sessions" = 0 && "$foundation_sessions" = 1 && "$preparation_seen" = false && "$later_seen" = false ]]; then
        printf 'Foundation session %s completed. To verify it and continue:\n  bash --noprofile --norc %s/company-guided-private.sh --continue-after-foundation %s %s %s\n' "$session" "$GP_PACKAGE" "$GP_FOUNDATION" "$GP_FULL" "$session"
      else
        printf 'Completed session %s is retained; this fresh command will not repeat it. IT must verify the next phase.\n' "$session"
      fi
    elif [[ -e "$directory/foundation-handoff.intent" || -e "$directory/preparation-handoff.intent" ]]; then
      printf 'Handoff session %s stopped during verification. Keep its records; ask IT to reconcile the failed check. Do not repeat earlier installation steps.\n' "$session"
    elif [[ "$IL_FOUND_REQUEST" = "$GP_FOUNDATION_SHA" ]]; then
      printf 'Foundation session %s needs IT reconciliation; automatic foundation replay is unavailable.\n' "$session"
    elif [[ -e "$directory/company-configuration.intent" && "$full_sessions" = 1 && "$later_seen" = false ]]; then
      printf 'Inspect the retained preparation evidence, then use the original explicit recovery command:\n  bash --noprofile --norc %s/company-prepare.sh --recover-preparation %s %s\n' "$GP_PACKAGE" "$GP_FULL" "$session"
    elif [[ -e "$directory/company-platform-store.intent" || "$session" = "$private_session" ]]; then
      printf 'Inspect the retained private-stage evidence, then use the original explicit recovery command:\n  bash --noprofile --norc %s/company-private-quota.sh --recover-private-quota %s %s\n' "$GP_PACKAGE" "$GP_FULL" "$session"
    else
      printf 'Session %s needs IT inspection of overlapping or unattributed records before any action.\n' "$session"
    fi
  done
)

_gp_intent() {
  printf -v text 'guided-private-intent-v1\noperation=%s\nfoundation=%s\nfull=%s\npackage=%s\n' "$GP_OPERATION" "$GP_FOUNDATION_SHA" "$GP_FULL_SHA" "$GP_PACKAGE_SHA"
}

_gp_handoff() {
  local kind=$1 predecessor=$2 intent=$3 text action outcome marker session request_sha stage nofile
  local planning=() verification=() arguments=()
  [[ "$predecessor" =~ ^s-[A-Za-z0-9]{12}$ ]] || _il_fail guided_predecessor_session
  _gp_intent
  _il_read "$intent"; [[ "$IL_TEXT" = "$text" ]] || _il_fail guided_original_intent_required
  IL_BASE=/etc/autosoft-install-admission; _il_context
  arguments=(--predecessor "$predecessor" --guided-package-sha "$GP_PACKAGE_SHA")
  if [[ "$kind" = foundation ]]; then
    request_sha=$GP_FOUNDATION_SHA
    arguments+=(--request "$GP_FOUNDATION" --worker-sha "$GP_FOUNDATION_WORKER_SHA" --full-request-sha "$GP_FULL_SHA")
    planning=("$GP_PACKAGE/company_install.py" --handoff-action)
    verification=("$GP_PACKAGE/company_install.py" --inspect-completed)
  else
    nofile=$(ulimit -Sn)
    if [[ "$nofile" != unlimited ]]; then
      [[ "$nofile" =~ ^[0-9]+$ ]] || _il_fail invalid_nofile_limit
      if (( nofile < 16384 )); then ulimit -Sn 16384 || _il_fail nofile_16384_required; fi
    fi
    request_sha=$GP_FULL_SHA
    arguments+=(--request "$GP_FULL")
    planning=("$GP_PACKAGE/company-native-retention.py" preparation-handoff-action)
    verification=("$GP_PACKAGE/company-native-retention.py" verify-completed-preparation)
  fi
  stage=$kind-handoff
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "${planning[@]}" "${arguments[@]}")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail guided_handoff_action
  _gp_recheck
  install_lock_acquire /etc/autosoft-install-admission "$request_sha" 30
  session=$IL_SESSION
  local parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" "$stage" "$action")
  printf 'Rechecking completed %s; no earlier step is repeated.\n' "$kind"
  install_lock_stage "$session" "$stage" "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC \
    /usr/bin/python3 -I -B "${verification[@]}" "${arguments[@]}" --parent "${parent[@]}"
  _gp_recheck
  install_lock_verify "$session" /usr/bin/python3 -I -B "${verification[@]}" "${arguments[@]}" --parent "${parent[@]}"
  _gp_recheck
  if [[ "$kind" = foundation ]]; then
    _il_read "/opt/autosoft-company/evidence/$GP_OPERATION/verified"; marker=$IL_TEXT
    outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
    [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = $'foundation-verified-v1\noperation='"$GP_OPERATION"$'\noutcome='"$outcome"$'\n' ]] || _il_fail guided_foundation_confirmation
  else
    _il_read "$IL_BASE/sessions/$predecessor/complete"
    outcome=${IL_TEXT#*$'\nfinal='}; outcome=${outcome%%$'\n'*}
    [[ "$outcome" =~ ^[a-f0-9]{64}$ ]] || _il_fail guided_preparation_confirmation
  fi
  install_lock_confirm_stage "$session" "$stage" "$action" "$outcome"
  install_lock_complete "$session" "$outcome"
  install_lock_release
  IL_OWNER=$BASHPID
}

company_guided_private_entry() {
  if [[ $# = 1 && $1 = --help ]]; then
    printf '%s\n' 'Guided private setup: development preview.' \
      'Usage: --install-private FOUNDATION_REQUEST FULL_REQUEST' \
      'After foundation: --continue-after-foundation FOUNDATION_REQUEST FULL_REQUEST FOUNDATION_SESSION' \
      'After preparation: --continue-after-preparation FOUNDATION_REQUEST FULL_REQUEST PREPARATION_SESSION' \
      'Read-only guidance: --private-status FOUNDATION_REQUEST FULL_REQUEST' \
      'Prepare setup inputs: --prepare-requests INDEPENDENT_DELIVERY_RECEIPT_SHA256' \
      'Read-only setup input guidance: --request-status INDEPENDENT_DELIVERY_RECEIPT_SHA256' \
      'Uses the original foundation, preparation and private quota commands.' \
      'Existing or interrupted work is preserved and must use explicit recovery.' \
      'Public startup, owner browser MFA, backups and complete installation remain pending.'
    return
  fi
  [[ ( $# = 2 && ( $1 = --prepare-requests || $1 = --request-status ) ) || ( $# = 3 && ( $1 = --install-private || $1 = --private-status ) ) || ( $# = 4 && ( $1 = --continue-after-foundation || $1 = --continue-after-preparation ) ) ]] || _il_fail guided_private_arguments_full_installation_unavailable
  _il_root; _il_utilities; IL_OWNER=$BASHPID
  GP_PACKAGE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  if [[ $1 = --prepare-requests || $1 = --request-status ]]; then
    _gp_package; _gp_delivery "$2"
    [[ -x /usr/bin/python3 ]] || _il_fail 'Request intake needs Python 3. Ask IT to use the authenticated prerequisite/bootstrap procedure; no packages or requests were changed.'
    local intake_command=status
    if [[ $1 = --prepare-requests ]]; then intake_command=collect; fi
    /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$GP_PACKAGE/company-request-intake.py" "$intake_command" --delivery-sha256 "$2"
    _gp_package; _gp_delivery "$2"
    return
  fi
  GP_FOUNDATION=$2; GP_FULL=$3
  _gp_package; _gp_pair
  if [[ $1 = --private-status ]]; then _gp_status; return; fi
  local intent="/opt/autosoft-company/guided-$GP_OPERATION.intent" text status
  GP_PHASE=preflight
  trap 'status=$?; trap - EXIT; if [[ ${IL_ACTIVE:-} = true ]]; then install_lock_release || status=74; fi; if ((status!=0)); then printf "Guided private setup stopped during %s. No later phase was started.\n" "${GP_PHASE:-preflight}" >&2; _gp_status >&2 || true; fi; exit "$status"' EXIT
  if [[ $1 = --continue-after-foundation || $1 = --continue-after-preparation ]]; then
    GP_PHASE=${1#--continue-after-}-handoff
    _gp_handoff "${1#--continue-after-}" "$4" "$intent"
  else
    if [[ -e "$intent" || -L "$intent" || -e "/opt/autosoft-company/evidence/$GP_OPERATION" || -L "/opt/autosoft-company/evidence/$GP_OPERATION" ]] || _gp_prior_session; then
      _gp_status || true
      _il_fail guided_existing_work_preserved_no_replay
    fi
    _il_ancestors "$intent"; _il_identity /opt/autosoft-company directory >/dev/null
    _gp_intent
    _il_write "$intent" "$text"
    GP_PHASE=foundation
    printf '[1/3] Preparing and independently verifying the encrypted foundation.\n'
    _gp_recheck
    /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /bin/bash --noprofile --norc "$GP_PACKAGE/company-install.sh" --foundation-only "$GP_FOUNDATION"
  fi
  if [[ $1 != --continue-after-preparation ]]; then
    GP_PHASE=preparation
    printf '[2/3] Collecting configuration and preparing the repository and runtime.\n'
    _gp_recheck
    /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /bin/bash --noprofile --norc "$GP_PACKAGE/company-prepare.sh" --prepare-foundation "$GP_FULL"
  fi
  GP_PHASE=private-initialization
  printf '[3/3] Verifying private infrastructure, identity and quota service.\n'
  _gp_recheck
  /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /bin/bash --noprofile --norc "$GP_PACKAGE/company-private-quota.sh" --retain-render-initialize-and-start-quota "$GP_FULL"
  _gp_recheck
  trap - EXIT
  printf '%s\n' 'Private setup finished through the independently verified child stages.' \
    'Public services remain gated. This is not a completed platform installation.'
}
company_guided_private_entry "$@"

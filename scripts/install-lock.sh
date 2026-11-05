#!/usr/bin/env bash
# Company installer API only. Sourcing this file performs no filesystem work.
# No installer wiring: completion assertions require independently checked effects.

_il_fail() { printf 'Installer admission refused: %s\n' "$1" >&2; exit 74; }
_il_root() { (( EUID == 0 )) || _il_fail root_required; }
_il_close_copies() {
  local descriptor
  for descriptor in "${IL_RECORD_FD:-}" "${IL_LOCK_FD:-}" "${IL_DIR_FD:-}"; do
    [[ -z "$descriptor" ]] || exec {descriptor}>&- || exit 74
  done
}
_il_tool() (
  _il_close_copies
  PATH=/usr/sbin:/usr/bin:/sbin:/bin; LC_ALL=C
  command "$@"
)
_il_hash() (
  _il_close_copies
  PATH=/usr/sbin:/usr/bin:/sbin:/bin; LC_ALL=C
  printf '%s' "$1" | command sha256sum
)
_il_child() (
  _il_close_copies
  unset IL_ACTIVE IL_OWNER IL_BASE IL_SESSION IL_REQUEST IL_LOCK_FD IL_DIR_FD IL_RECORD_FD
  exec "$@"
)
_il_take_lock() (
  # flock receives only the lock descriptor, never the namespace descriptor.
  if [[ -n ${IL_DIR_FD:-} ]]; then exec {IL_DIR_FD}>&- || exit 74; fi
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  command flock -x -w "$1" "$IL_LOCK_FD"
)
_il_utilities() {
  local name
  for name in stat mkdir mktemp chmod sync sha256sum flock; do
    _il_tool test -x "/usr/bin/$name" || _il_tool test -x "/bin/$name" || _il_fail missing_utility
  done
  [[ ${BASH_VERSINFO[0]} -ge 4 ]] || _il_fail unsupported_shell
}
_il_path() {
  [[ "$1" =~ ^/[A-Za-z0-9_./-]+$ && "$1" != / && "$1" != */ && "$1" != *//* && "$1" != */./* && "$1" != */../* && "$1" != */. && "$1" != */.. ]] || _il_fail invalid_path
}
_il_metadata() {
  local metadata
  metadata=$(_il_tool stat ${2:+-L} -c '%d:%i:%f:%u:%g:%a:%h:%s:%.Y:%.Z' -- "$1") || _il_fail metadata_unavailable
  [[ "$metadata" =~ ^[0-9]+:[0-9]+:[0-9a-f]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:-?[0-9]+\.[0-9]+:-?[0-9]+\.[0-9]+$ ]] || _il_fail malformed_metadata
  printf '%s' "$metadata"
}
_il_identity() {
  local metadata dev ino bits uid gid mode links size modified changed
  [[ ! -L "$1" ]] || _il_fail symbolic_object
  metadata=$(_il_metadata "$1") || _il_fail metadata_unavailable
  IFS=: read -r dev ino bits uid gid mode links size modified changed <<< "$metadata"
  [[ "$uid" = 0 && "$gid" = 0 ]] || _il_fail foreign_owner
  case "$2" in
    ancestor)
      [[ -d "$1" ]] && (( (8#$mode & 8#022) == 0 )) || _il_fail unsafe_ancestor
      printf '%s:%s:%s:%s:%s:%s' "$dev" "$ino" "$bits" "$uid" "$gid" "$mode" ;;
    directory)
      [[ -d "$1" && "$mode" = 700 ]] || _il_fail unsafe_directory
      printf '%s:%s:%s:%s:%s:%s' "$dev" "$ino" "$bits" "$uid" "$gid" "$mode" ;;
    file)
      [[ -f "$1" && "$mode" = 600 && "$links" = 1 && "$size" -le 4096 ]] || _il_fail unsafe_file
      printf '%s' "$metadata" ;;
    *) _il_fail invalid_object_kind ;;
  esac
}
_il_ancestors() {
  local parent=${1%/*}
  [[ -n "$parent" ]] || parent=/
  while :; do
    _il_identity "$parent" ancestor >/dev/null || _il_fail unsafe_ancestor
    [[ "$parent" != / ]] || break
    parent=${parent%/*}; [[ -n "$parent" ]] || parent=/
  done
}
_il_fd_identity() {
  local metadata dev ino bits uid gid mode links size modified changed
  metadata=$(_il_metadata "/proc/$IL_OWNER/fd/$1" follow) || _il_fail held_descriptor_unavailable
  IFS=: read -r dev ino bits uid gid mode links size modified changed <<< "$metadata"
  if [[ "$2" = directory ]]; then
    printf '%s:%s:%s:%s:%s:%s' "$dev" "$ino" "$bits" "$uid" "$gid" "$mode"
  else printf '%s' "$metadata"; fi
}
_il_read() {
  local before after body='' status size
  local LC_ALL=C
  [[ -z ${IL_RECORD_FD:-} ]] || _il_fail nested_record_read
  before=$(_il_identity "$1" file) || _il_fail invalid_record
  size=${before#*:*:*:*:*:*:*:}; size=${size%%:*}
  exec {IL_RECORD_FD}<"$1" || _il_fail record_open_unavailable
  [[ $(_il_fd_identity "$IL_RECORD_FD" file) = "$before" ]] || _il_fail record_replaced
  if IFS= read -r -d '' -n 4097 body <&"$IL_RECORD_FD"; then status=0; else status=$?; fi
  [[ "$status" = 1 && ${#body} = "$size" ]] || _il_fail malformed_record
  after=$(_il_identity "$1" file) || _il_fail record_replaced
  [[ "$before" = "$after" && $(_il_fd_identity "$IL_RECORD_FD" file) = "$before" ]] || _il_fail record_replaced
  exec {IL_RECORD_FD}<&- || _il_fail record_close_unavailable
  unset IL_RECORD_FD
  IL_TEXT=$body
}
_il_write() {
  local path=$1 text=$2 parent=${1%/*}
  [[ ! -e "$path" && ! -L "$path" ]] || _il_fail existing_record
  (_il_close_copies; umask 077; set -o noclobber; printf '%s' "$text" > "$path") || _il_fail record_write_unavailable
  _il_tool sync -f -- "$path" || _il_fail record_sync_unavailable
  _il_tool sync -f -- "$parent" || _il_fail directory_sync_unavailable
  _il_read "$path"
  [[ "$IL_TEXT" = "$text" ]] || _il_fail record_readback_mismatch
}
_il_context() {
  local entry count=0 expected directory lock sessions filesystem digest
  _il_path "$IL_BASE"; _il_ancestors "$IL_BASE"
  directory=$(_il_identity "$IL_BASE" directory) || _il_fail invalid_namespace
  lock=$(_il_identity "$IL_BASE/install.lock" file) || _il_fail invalid_lock
  [[ ${lock#*:*:*:*:*:*:*:} = 0:* ]] || _il_fail nonempty_lock
  sessions=$(_il_identity "$IL_BASE/sessions" directory) || _il_fail invalid_sessions_directory
  filesystem=$(_il_tool stat -f -c %T -- "$IL_BASE") || _il_fail filesystem_unavailable
  case "$filesystem" in ext2/ext3|xfs|btrfs) ;; *) _il_fail unsupported_filesystem ;; esac
  for entry in "$IL_BASE"/* "$IL_BASE"/.[!.]* "$IL_BASE"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    case "${entry##*/}" in install.lock|binding|sessions) ;; *) _il_fail unknown_namespace_object ;; esac
    ((count+=1)); ((count<=3)) || _il_fail namespace_inventory_limit
  done
  ((count==3)) || _il_fail incomplete_namespace
  printf -v expected 'install-lock-v1\nbase=%s\ndirectory=%s\nlock=%s\nsessions=%s\nfilesystem=%s\n' "$IL_BASE" "$directory" "$lock" "$sessions" "$filesystem"
  _il_read "$IL_BASE/binding"
  [[ "$IL_TEXT" = "$expected" ]] || _il_fail namespace_binding_mismatch
  digest=$(_il_hash "$expected") || _il_fail digest_unavailable
  IL_BINDING=${digest%% *}; [[ "$IL_BINDING" =~ ^[0-9a-f]{64}$ ]] || _il_fail malformed_digest
  IL_DIRECTORY_BINDING=$directory; IL_LOCK_BINDING=$lock
  if [[ ${IL_ACTIVE:-} = true ]]; then
    [[ "$BASHPID" = "$IL_OWNER" && $(_il_fd_identity "$IL_DIR_FD" directory) = "$directory" && $(_il_fd_identity "$IL_LOCK_FD" file) = "$lock" ]] || _il_fail held_scope_mismatch
  fi
}
_il_live() {
  [[ ${IL_ACTIVE:-} = true && "$BASHPID" = "${IL_OWNER:-}" && "$1" = "${IL_SESSION:-}" ]] || _il_fail foreign_or_released_session
  _il_context
  _il_session_intent "$IL_BASE/sessions/$IL_SESSION" "$IL_SESSION"
  [[ "$IL_REQUEST" = "$IL_FOUND_REQUEST" ]] || _il_fail session_request_mismatch
  [[ ! -e "$IL_BASE/sessions/$IL_SESSION/complete" && ! -L "$IL_BASE/sessions/$IL_SESSION/complete" ]] || _il_fail already_completed
}
_il_session_intent() {
  local directory=$1 id=$2 binding expected request
  [[ "$id" =~ ^s-[A-Za-z0-9]{12}$ ]] || _il_fail invalid_session_id
  binding=$(_il_identity "$directory" directory) || _il_fail invalid_session_directory
  _il_read "$directory/intent"
  request=${IL_TEXT#*$'\n'request=}; request=${request%%$'\n'*}
  [[ "$request" =~ ^[0-9a-f]{64}$ ]] || _il_fail malformed_session_intent
  printf -v expected 'install-session-v1\nsession=%s\nrequest=%s\nbinding=%s\ndirectory=%s\nclosed=true\n' "$id" "$request" "$IL_BINDING" "$binding"
  [[ "$IL_TEXT" = "$expected" ]] || _il_fail session_binding_mismatch
  IL_FOUND_REQUEST=$request
}
_il_stage_intent() {
  local expected
  printf -v expected 'install-stage-v1\nsession=%s\nstage=%s\naction=%s\nclosed=true\n' "$1" "$2" "$3"
  _il_read "$IL_BASE/sessions/$1/$2.intent"
  [[ "$IL_TEXT" = "$expected" ]] || _il_fail stage_binding_mismatch
}
_il_stage_inventory() {
  local directory=$1 id=$2 entry name label action outcome expected manifest='' count=0 total=0 digest
  local LC_ALL=C
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    ((total+=1)); ((total<=130)) || _il_fail stage_inventory_limit
    name=${entry##*/}
    case "$name" in
      intent|complete) _il_identity "$entry" file >/dev/null || _il_fail invalid_session_record ;;
      *.intent|*.confirmed)
        label=${name%.*}; [[ "$label" =~ ^[a-z][a-z0-9-]{0,47}$ ]] || _il_fail invalid_stage_label
        [[ -f "$directory/$label.intent" && -f "$directory/$label.confirmed" ]] || _il_fail unresolved_stage
        if [[ "$name" = *.confirmed ]]; then continue; fi
        ((count+=1)); ((count<=64)) || _il_fail stage_inventory_limit
        _il_read "$entry"
        action=${IL_TEXT#*$'\n'action=}; action=${action%%$'\n'*}
        [[ "$action" =~ ^[0-9a-f]{64}$ ]] || _il_fail invalid_stage_action
        _il_stage_intent "$id" "$label" "$action"
        _il_read "$directory/$label.confirmed"
        outcome=${IL_TEXT#*$'\n'outcome=}; outcome=${outcome%%$'\n'*}
        [[ "$outcome" =~ ^[0-9a-f]{64}$ ]] || _il_fail invalid_stage_outcome
        printf -v expected 'install-stage-confirmed-v1\nsession=%s\nstage=%s\naction=%s\noutcome=%s\nindependently_confirmed=true\n' "$id" "$label" "$action" "$outcome"
        [[ "$IL_TEXT" = "$expected" ]] || _il_fail stage_confirmation_mismatch
        manifest+=$expected ;;
      *) _il_fail unknown_session_object ;;
    esac
  done
  ((count>=1)) || _il_fail no_confirmed_stage
  digest=$(_il_hash "$manifest") || _il_fail digest_unavailable
  IL_MANIFEST=${digest%% *}; [[ "$IL_MANIFEST" =~ ^[0-9a-f]{64}$ ]] || _il_fail malformed_digest
}
_il_history() {
  local directory id request outcome expected count=0
  for directory in "$IL_BASE/sessions"/* "$IL_BASE/sessions"/.[!.]* "$IL_BASE/sessions"/..?*; do
    [[ -e "$directory" || -L "$directory" ]] || continue
    ((count+=1)); ((count<=1024)) || _il_fail session_inventory_limit
    id=${directory##*/}; _il_session_intent "$directory" "$id"; request=$IL_FOUND_REQUEST
    _il_stage_inventory "$directory" "$id"
    _il_read "$directory/complete"
    outcome=${IL_TEXT#*$'\n'final=}; outcome=${outcome%%$'\n'*}
    [[ "$outcome" =~ ^[0-9a-f]{64}$ ]] || _il_fail unresolved_session
    printf -v expected 'install-complete-v1\nsession=%s\nrequest=%s\nmanifest=%s\nfinal=%s\nindependently_confirmed=true\n' "$id" "$request" "$IL_MANIFEST" "$outcome"
    [[ "$IL_TEXT" = "$expected" ]] || _il_fail completion_binding_mismatch
  done
}
_il_prior_stages() {
  local directory="$IL_BASE/sessions/$IL_SESSION" entry name count=0 total=0
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    ((total+=1)); ((total<=129)) || _il_fail stage_inventory_limit
    name=${entry##*/}
    case "$name" in
      intent) ;;
      *.intent|*.confirmed)
        [[ "${name%.*}" =~ ^[a-z][a-z0-9-]{0,47}$ ]] || _il_fail invalid_stage_label
        [[ -f "$directory/${name%.*}.intent" && -f "$directory/${name%.*}.confirmed" ]] || _il_fail unresolved_stage
        if [[ "$name" = *.intent ]]; then ((count+=1)); fi ;;
      *) _il_fail unknown_session_object ;;
    esac
    _il_identity "$entry" file >/dev/null || _il_fail invalid_stage_record
  done
  ((count<64)) || _il_fail stage_inventory_limit
  # A later stage is not admitted while an earlier effect remains unconfirmed.
  if ((count>0)); then _il_stage_inventory "$directory" "$IL_SESSION"; fi
}

install_lock_initialize() {
  local base=${1:?private namespace required} directory lock sessions filesystem expected
  _il_root; _il_utilities; _il_path "$base"; _il_ancestors "$base"
  [[ -z ${IL_ACTIVE:-} && ! -e "$base" && ! -L "$base" ]] || _il_fail existing_namespace
  _il_tool mkdir -m 0700 -- "$base" "$base/sessions" || _il_fail initialization_unavailable
  (_il_close_copies; umask 077; set -o noclobber; : > "$base/install.lock") || _il_fail initialization_unavailable
  IL_BASE=$base; IL_OWNER=$BASHPID
  directory=$(_il_identity "$base" directory) || _il_fail initialization_unavailable
  lock=$(_il_identity "$base/install.lock" file) || _il_fail initialization_unavailable
  sessions=$(_il_identity "$base/sessions" directory) || _il_fail initialization_unavailable
  filesystem=$(_il_tool stat -f -c %T -- "$base") || _il_fail filesystem_unavailable
  case "$filesystem" in ext2/ext3|xfs|btrfs) ;; *) _il_fail unsupported_filesystem ;; esac
  printf -v expected 'install-lock-v1\nbase=%s\ndirectory=%s\nlock=%s\nsessions=%s\nfilesystem=%s\n' "$base" "$directory" "$lock" "$sessions" "$filesystem"
  _il_tool sync -f -- "$base/install.lock" || _il_fail initialization_sync_unavailable
  _il_tool sync -f -- "$base/sessions" || _il_fail initialization_sync_unavailable
  _il_write "$base/binding" "$expected"
  _il_tool sync -f -- "${base%/*}" || _il_fail initialization_sync_unavailable
  _il_context
}
install_lock_acquire() {
  local base=${1:?private namespace required} request=${2:?request digest required} wait=${3:?bounded wait required} directory id binding expected
  _il_root; _il_utilities
  [[ -z ${IL_ACTIVE:-} && "$request" =~ ^[0-9a-f]{64}$ && "$wait" =~ ^([1-9]|[12][0-9]|30)$ ]] || _il_fail invalid_acquisition
  IL_BASE=$base; IL_OWNER=$BASHPID; _il_context
  exec {IL_DIR_FD}<"$base" || _il_fail directory_open_unavailable
  exec {IL_LOCK_FD}<"$base/install.lock" || _il_fail lock_open_unavailable
  IL_ACTIVE=true
  _il_context
  _il_take_lock "$wait" || _il_fail lock_wait_unavailable
  _il_context; _il_history; _il_context
  directory=$(_il_tool mktemp -d -- "$base/sessions/s-XXXXXXXXXXXX") || _il_fail session_creation_unavailable
  id=${directory##*/}; [[ "$directory" = "$base/sessions/$id" && "$id" =~ ^s-[A-Za-z0-9]{12}$ ]] || _il_fail invalid_session_id
  binding=$(_il_identity "$directory" directory) || _il_fail invalid_session_directory
  IL_SESSION=$id; IL_REQUEST=$request
  printf -v expected 'install-session-v1\nsession=%s\nrequest=%s\nbinding=%s\ndirectory=%s\nclosed=true\n' "$id" "$request" "$IL_BINDING" "$binding"
  _il_write "$directory/intent" "$expected"
  _il_context; _il_session_intent "$directory" "$id"
}
install_lock_stage() {
  local session=${1:?session required} label=${2:?stage required} action=${3:?action digest required} expected status
  shift 3
  [[ "$label" =~ ^[a-z][a-z0-9-]{0,47}$ && "$action" =~ ^[0-9a-f]{64}$ && $# -gt 0 ]] || _il_fail invalid_stage
  _il_live "$session"
  _il_prior_stages
  printf -v expected 'install-stage-v1\nsession=%s\nstage=%s\naction=%s\nclosed=true\n' "$session" "$label" "$action"
  _il_write "$IL_BASE/sessions/$session/$label.intent" "$expected"
  _il_live "$session"; _il_stage_intent "$session" "$label" "$action"
  if _il_child "$@"; then status=0; else status=$?; fi
  _il_live "$session"; _il_stage_intent "$session" "$label" "$action"
  return "$status"
}
install_lock_confirm_stage() {
  local session=${1:?session required} label=${2:?stage required} action=${3:?action digest required} outcome=${4:?independently verified evidence digest required} expected
  [[ "$label" =~ ^[a-z][a-z0-9-]{0,47}$ && "$action" =~ ^[0-9a-f]{64}$ && "$outcome" =~ ^[0-9a-f]{64}$ ]] || _il_fail invalid_confirmation
  _il_live "$session"; _il_stage_intent "$session" "$label" "$action"
  printf -v expected 'install-stage-confirmed-v1\nsession=%s\nstage=%s\naction=%s\noutcome=%s\nindependently_confirmed=true\n' "$session" "$label" "$action" "$outcome"
  _il_write "$IL_BASE/sessions/$session/$label.confirmed" "$expected"
  _il_live "$session"
}
install_lock_complete() {
  local session=${1:?session required} outcome=${2:?independently verified final evidence digest required} expected
  [[ "$outcome" =~ ^[0-9a-f]{64}$ ]] || _il_fail invalid_final_evidence
  _il_live "$session"; _il_stage_inventory "$IL_BASE/sessions/$session" "$session"
  printf -v expected 'install-complete-v1\nsession=%s\nrequest=%s\nmanifest=%s\nfinal=%s\nindependently_confirmed=true\n' "$session" "$IL_REQUEST" "$IL_MANIFEST" "$outcome"
  _il_write "$IL_BASE/sessions/$session/complete" "$expected"
  _il_context; _il_history
}
install_lock_release() {
  [[ ${IL_ACTIVE:-} = true && "$BASHPID" = "${IL_OWNER:-}" ]] || _il_fail foreign_or_released_session
  _il_context
  # Invalidate scope before closing either FD; releasing is never completion.
  unset IL_ACTIVE IL_SESSION IL_REQUEST
  exec {IL_LOCK_FD}<&- || _il_fail lock_close_unavailable
  exec {IL_DIR_FD}<&- || _il_fail directory_close_unavailable
  unset IL_LOCK_FD IL_DIR_FD IL_OWNER
}

# Read-only company verification dispatch. Status never asserts stage effects.
_il_verification_child() (
  set +x +v
  _il_close_copies
  cd / || exit 74
  # Clear the environment before loading env itself (including loader variables).
  exec -c /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC "$@"
  exit 74
)
install_lock_verify() {
  local LC_ALL=C session argument total=0 before after status
  (( $# >= 2 && $# <= 34 )) || _il_fail invalid_verification_argv
  for argument in "$@"; do
    (( ${#argument} <= 4096 )) || _il_fail verification_argument_limit
    ((total+=${#argument}+1))
    ((total<=65536)) || _il_fail verification_argv_limit
  done
  session=$1; shift
  _il_path "$1"
  [[ -f /usr/bin/env && -x /usr/bin/env ]] || _il_fail verification_environment_unavailable
  _il_live "$session"
  before=$(_il_identity "$IL_BASE/sessions/$session/intent" file) || _il_fail invalid_verification_record
  [[ -z ${IL_RECORD_FD:-} ]] || _il_fail nested_record_read
  exec {IL_RECORD_FD}<"$IL_BASE/sessions/$session/intent" || _il_fail verification_record_open_unavailable
  [[ $(_il_fd_identity "$IL_RECORD_FD" file) = "$before" ]] || _il_fail verification_record_replaced
  if _il_verification_child "$@"; then status=0; else status=$?; fi
  after=$(_il_identity "$IL_BASE/sessions/$session/intent" file) || _il_fail verification_record_replaced
  [[ "$after" = "$before" && $(_il_fd_identity "$IL_RECORD_FD" file) = "$before" ]] || _il_fail verification_record_replaced
  exec {IL_RECORD_FD}<&- || _il_fail verification_record_close_unavailable
  unset IL_RECORD_FD
  _il_live "$session"
  return "$status"
}

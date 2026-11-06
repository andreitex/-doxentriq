#!/usr/bin/env bash
# Store -> Source -> stored startup -> fresh render, under one live admission parent.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@

company_render_entry() {
  [[ $# = 2 && $1 = --retain-inspect-and-render ]] || _il_fail continuation_only_required
  _il_root
  local request=$2 package worker expected actual request_sha operation stage action outcome verification status
  local store_outcome='' final_outcome='' marker='' session='' nofile='' source_outcome=''
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
  _il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" continuation-ready --request "$request"
  _il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" render-ready --request "$request"
  install_lock_acquire /etc/autosoft-install-admission "$request_sha" 30
  trap 'status=$?; trap - EXIT; if [[ ${IL_ACTIVE:-} = true ]]; then install_lock_release || status=74; fi; exit "$status"' EXIT
  session=$IL_SESSION
  # Producer copies the exact existing retention-only stage loop, not its
  # session completion. Both outcomes stay in this SAME live parent session.
# @EMBED_RETENTION_STAGE_LOOP@
  source_outcome=$outcome
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" startup-action --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail stored_startup_action
  local parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" company-stored-startup "$action")
  if ! install_lock_stage "$session" company-stored-startup "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" inspect-stored-startup --request "$request" --parent "${parent[@]}"; then
    _il_fail stored_startup_child_failed_preserve_evidence
  fi
  install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" verify-stored-startup --request "$request" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/company-stored-startup/confirmation"
  marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = $'stored-startup-verified-v1\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage=company-stored-startup\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail stored_startup_confirmation_binding
  install_lock_confirm_stage "$session" company-stored-startup "$action" "$outcome"
  local startup_outcome=$outcome
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" render-action --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail render_action
  parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" company-render "$action")
  if ! install_lock_stage "$session" company-render "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" render-configuration --request "$request" --parent "${parent[@]}"; then
    _il_fail render_child_failed_preserve_evidence
  fi
  install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" verify-render --request "$request" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/company-render/confirmation"
  marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = $'render-verified-v1\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage=company-render\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail render_confirmation_binding
  install_lock_confirm_stage "$session" company-render "$action" "$outcome"
  final_outcome=$(_il_hash "render-only-v1:$request_sha:$store_outcome:$source_outcome:$startup_outcome:$outcome"); final_outcome=${final_outcome%% *}
  install_lock_complete "$session" "$final_outcome"
  printf 'Signed source retained and configuration rendered and independently verified. Identity, service activation and recovery acceptance remain incomplete.\n'
}
company_render_entry "$@"

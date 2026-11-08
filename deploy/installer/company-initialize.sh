#!/usr/bin/env bash
# Store -> Source -> startup -> render -> private infrastructure -> identity, one live parent.
set -Eeuo pipefail
set +x +v
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C LANG=C TZ=UTC; export LC_ALL LANG TZ
# @EMBED_INSTALL_LOCK@

company_initialize_entry() {
  [[ $# = 2 && $1 = --retain-render-and-initialize-private ]] || _il_fail continuation_only_required
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
  _il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" infrastructure-ready --request "$request"
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
  local render_outcome=$outcome
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" infrastructure-action --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail infrastructure_action
  parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" company-private-infrastructure "$action")
  if ! install_lock_stage "$session" company-private-infrastructure "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" initialize-private-infrastructure --request "$request" --parent "${parent[@]}"; then
    _il_fail private_infrastructure_child_failed_preserve_evidence
  fi
  install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" verify-private-infrastructure --request "$request" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/company-private-infrastructure/confirmation"
  marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = $'private-infrastructure-verified-v1\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage=company-private-infrastructure\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail private_infrastructure_confirmation_binding
  install_lock_confirm_stage "$session" company-private-infrastructure "$action" "$outcome"
  local infrastructure_outcome=$outcome
  printf 'Private services confirmed. Provisioning the initial identity policy.\n'
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" identity-action --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail initial_identity_action
  parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" company-initial-identity "$action")
  if ! install_lock_stage "$session" company-initial-identity "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" provision-initial-identity --request "$request" --parent "${parent[@]}"; then
    _il_fail identity_provisioning_uncertain_preserve_records_do_not_retry
  fi
  install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" verify-initial-identity --request "$request" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/company-initial-identity/confirmation"
  marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = $'initial-identity-verified-v1\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage=company-initial-identity\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail initial_identity_confirmation_binding
  install_lock_confirm_stage "$session" company-initial-identity "$action" "$outcome"
  final_outcome=$(_il_hash "private-initialization-only-v1:$request_sha:$store_outcome:$source_outcome:$startup_outcome:$render_outcome:$infrastructure_outcome:$outcome"); final_outcome=${final_outcome%% *}
  install_lock_complete "$session" "$final_outcome"
  printf 'Private infrastructure and initial identity policy independently verified. Public startup, browser MFA, backups and reboot recovery remain pending.\n'
}
company_initialize_entry "$@"

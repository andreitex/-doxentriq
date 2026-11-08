# Embedded only by the company producer after initial identity confirmation.
  local identity_outcome=$outcome
  printf 'Initial identity confirmed. Starting private storage support.\n'
  action=$(_il_tool /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" quota-action --request "$request")
  [[ "$action" =~ ^[a-f0-9]{64}$ ]] || _il_fail private_quota_action
  parent=("$BASHPID" "$IL_DIR_FD" "$IL_LOCK_FD" "$session" "$request_sha" company-private-quota "$action")
  if ! install_lock_stage "$session" company-private-quota "$action" /usr/bin/env -i PATH="$PATH" LC_ALL=C LANG=C HOME=/ TZ=UTC /usr/bin/python3 -I -B "$worker" activate-private-quota --request "$request" --parent "${parent[@]}"; then
    _il_fail private_quota_uncertain_preserve_records_do_not_retry
  fi
  install_lock_verify "$session" /usr/bin/python3 -I -B "$worker" verify-private-quota --request "$request" --parent "${parent[@]}"
  _il_read "/opt/autosoft-company/evidence/$operation/company-private-quota/confirmation"
  marker=$IL_TEXT; outcome=${marker#*$'\noutcome='}; outcome=${outcome%%$'\n'*}
  [[ "$outcome" =~ ^[a-f0-9]{64}$ && "$marker" = $'private-quota-verified-v1\nrequest='"$request_sha"$'\nsession='"$session"$'\nstage=company-private-quota\naction='"$action"$'\noutcome='"$outcome"$'\n' ]] || _il_fail private_quota_confirmation_binding
  install_lock_confirm_stage "$session" company-private-quota "$action" "$outcome"
  final_outcome=$(_il_hash "private-quota-support-only-v1:$request_sha:$store_outcome:$source_outcome:$startup_outcome:$render_outcome:$infrastructure_outcome:$identity_outcome:$outcome"); final_outcome=${final_outcome%% *}
  install_lock_complete "$session" "$final_outcome"
  printf 'Private identity and storage support independently verified. Public services, operational timers, browser MFA and backup acceptance remain pending.\n'

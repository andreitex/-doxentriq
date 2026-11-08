# Embedded only by the company producer after initial identity confirmation.
  local identity_outcome=$outcome
  printf 'Initial identity confirmed. Starting private storage support.\n'
  _ci_step company-private-quota quota-action activate-private-quota verify-private-quota private-quota-verified-v1
  final_outcome=$(_il_hash "private-quota-support-only-v1:$request_sha:$store_outcome:$source_outcome:$startup_outcome:$render_outcome:$infrastructure_outcome:$identity_outcome:$outcome"); final_outcome=${final_outcome%% *}
  install_lock_complete "$session" "$final_outcome"
  printf 'Private identity and storage support independently verified. Public services, operational timers, browser MFA and backup acceptance remain pending.\n'

# Identity setup request handling

The company Keycloak helper sends every request to the fixed internal HTTPS
identity endpoint. Client creation now uses the same redirect refusal and
request deadline as the other identity operations. Empty successful creation
responses are accepted without depending on a `Content-Length` header.

Protected input is limited to 64 KiB, responses to 1 MiB, each request to 15
seconds, and the complete helper operation to two minutes. That operation
deadline includes reading protected input. Invalid JSON and network errors use
fixed diagnostics so an upstream response cannot place credentials in logs.
Credentials still enter through standard input rather than process arguments.

Neither the helper nor the bootstrap caller automatically repeats a failed
provisioning operation. An interrupted request may already have created a
client or assigned a role. Installation stops and tells IT to inspect the
identity service before retrying. The caller uses an already-present image
and refuses an implicit image pull.

The transport tests cover fresh and existing clients, empty creation responses,
redirect/error refusal, uncertain mutations, size limits, stalled requests,
stalled input, redaction and password-only owner recovery. The caller tests
verify a single attempt, protected input and explicit failure handling. These
are local component tests with synthetic identity responses, not live login or
clean-install acceptance.

The native installation worker still needs bounded Docker process/container
supervision and an authenticated helper file readable by its container user.
Those integration requirements must be completed before activating identity
on the fresh VM. The helper deadline alone cannot bound a Docker daemon that
never starts the container.

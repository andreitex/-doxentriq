# Control and worker shutdown

Control and worker processes handle SIGINT and SIGTERM before startup completes. One 50-second deadline covers startup completion, admitted HTTP requests, background recovery/observation/reconciliation, development jobs, RabbitMQ jobs and confirmed outbox transactions, connection closure and finally storage closure. New background jobs and queue deliveries stop immediately; RabbitMQ consumption is cancelled and late deliveries are requeued. Existing SSE responses use the server's existing pre-close hook.

Acknowledgements always belong to the channel that delivered the job. A disconnected channel's delivery is left for broker redelivery; a replacement channel never acknowledges it. A connect or consume operation completing during shutdown is retained, cancelled and closed. The final publisher drains pending outbox batches after admitted work finishes, while unavailable broker connections leave unpublished records durable.

Repeated signals share the same shutdown result. The process exits zero only after every phase completes; failures and expiry exit nonzero without advancing to storage closure. A deadline stops waiting and then terminates the process. It does not confirm cancellation of a model request, payment, invoice, email or other external operation. Running calls, held reservations and uncertain external outcomes keep their existing durable recovery rules. This change never rewrites them to cancelled or succeeded.

Injected connection, job, timer and storage tests qualify local ordering and race behavior. They do not qualify live RabbitMQ/MySQL interruption, container stop timing, abrupt process kill, power loss or coordinated backups. The container grace period must exceed the 50-second process budget.

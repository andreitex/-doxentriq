# HTTP work during shutdown

Control tracks the actual lifetime of route handlers, global and per-route request hooks, and explicitly registered not-found handlers. The wrappers are installed before authentication and plugin registration and are inherited by encapsulated plugins. A disconnected client or an already-sent response does not release a returned promise or an outstanding callback, including default/rest callback parameters.

The existing pre-close hook shuts HTTP and SSE admission, responses, timers and subscriptions synchronously, then waits for admitted function invocations and SSE reads. Later pipeline phases cannot start business work once admission closes. Open responses receive a bounded 503; response/error/abort phases complete without invoking new business callbacks.

The existing whole-process 50-second deadline covers this drain. No new timeout or cancellation of providers/external operations is introduced. Function context, arguments, callback payloads, promise rejection and Fastify's invalid-function checks remain enforced. Business work must be represented by its returned promise or explicit callback; detached tasks are not implicitly recoverable HTTP work. A hook that sends a response must also return its completion promise/reply or finish its callback. Otherwise shutdown conservatively waits until the outer deadline, because socket completion cannot prove that callback work has finished.

Local loopback and in-memory controls verify callback/promise lifetimes, client interruption, early response delivery and routing/plugin semantics. They do not qualify live identity providers, MySQL/RabbitMQ, VM/container-stop behavior, power loss or coordinated backups.

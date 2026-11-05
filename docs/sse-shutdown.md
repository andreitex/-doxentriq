# Progress streams during shutdown

Fastify's pre-close hook closes progress-stream admission, synchronously ends responses, stops their timers and removes subscriptions, then waits for every admitted progress read to settle. The route checks admission before its initial job-existence read and tracks that read before it starts. An in-flight read remains tracked even if its client disconnected before shutdown, including before a stream or subscription exists. Subscriber callbacks and reads completing afterward cannot produce more stream writes.

The hook has no separate timeout. The control process's shared 50-second shutdown budget covers it. A read that exceeds that budget causes nonzero termination while running and uncertain records retain their existing recovery rules. A timed-out shutdown never advances to connection or storage closure, even if a read settles later.

The local controls exercise the actual Fastify instance and SSE route through in-memory injection with delayed Store.read callbacks. They cover shutdown, client disconnection during initial admission or replay, subscriber wakeups, refusal to create streams after admission closes, read failure and the outer deadline. They do not open sockets or qualify live browser, Redis, MySQL, container-stop or process-kill behavior.

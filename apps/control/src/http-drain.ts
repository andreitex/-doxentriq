import { errorCodes, type FastifyInstance, type FastifyReply } from 'fastify';

const hookCallbacks: Record<string, number> = { onRequest: 2, preParsing: 3, preValidation: 2, preSerialization: 3, preHandler: 2, onSend: 3, onResponse: 2, onError: 3, onTimeout: 2, onRequestAbort: 1 };
type Callable = (this: unknown, ...args: any[]) => any;
const unavailable = { error: { message: 'The service is shutting down; reconnect to replay recorded progress.', code: 503 } };

/** Track actual returned-promise/callback lifetimes, independently of sockets. */
export class HttpDrain {
  private closed = false;
  private pending = new Set<Promise<void>>();
  private wrappers = new WeakMap<Callable, { name: string; original: Callable }>();
  private cached = new WeakMap<Callable, Map<string, Callable>>();
  private installed = new WeakSet<FastifyInstance>();
  stopAdmission(): void { this.closed = true; }
  async drain(): Promise<void> { while (this.pending.size) await Promise.all([...this.pending]); }

  private validate(name: string, fn: Callable): void {
    if (fn.constructor.name !== 'AsyncFunction') return;
    const invalid = name === 'onRequestAbort' ? fn.length !== 1 : fn.length === (hookCallbacks[name]! + 1);
    if (invalid) throw new errorCodes.FST_ERR_HOOK_INVALID_ASYNC_HANDLER();
  }
  private deny(name: string, args: any[]): any {
    const callback = name === 'handler' ? undefined : args[hookCallbacks[name]!];
    const reply = name === 'onRequestAbort' ? undefined : args[1] as FastifyReply | undefined;
    if (!reply || reply.sent || reply.raw.destroyed || reply.raw.writableEnded || ['onResponse', 'onError'].includes(name)) return typeof callback === 'function' ? callback() : undefined;
    if (name === 'onSend' || name === 'preSerialization') {
      reply.code(503).header('content-type', 'application/json; charset=utf-8');
      const payload = name === 'onSend' ? JSON.stringify(unavailable) : unavailable;
      return typeof callback === 'function' ? callback(null, payload) : Promise.resolve(payload);
    }
    return reply.code(503).send(unavailable);
  }
  private wrap(name: string, fn: Callable, validate = true): Callable {
    const prior = this.wrappers.get(fn);
    if (prior?.name === name) return fn;
    if (prior) fn = prior.original;
    if (validate && name !== 'handler') this.validate(name, fn);
    let variants = this.cached.get(fn); if (!variants) { variants = new Map(); this.cached.set(fn, variants); }
    const existing = variants.get(name); if (existing) return existing;
    const tracker = this, callbackIndex = name === 'handler' ? undefined : hookCallbacks[name];
    const wrapped: Callable = function (this: unknown, ...args: any[]) {
      if (tracker.closed) return tracker.deny(name, args);
      let finish!: () => void; const lifetime = new Promise<void>(resolve => { finish = resolve; }); tracker.pending.add(lifetime);
      let settled = false, returned = false, callbackCalled = false, promiseReturned = false;
      const release = () => { if (settled) return; settled = true; tracker.pending.delete(lifetime); finish(); };
      // Default/rest parameters hide arity. Fastify's actual callback slot,
      // rather than Function.length, determines callback lifetime.
      const callbackStyle = callbackIndex !== undefined && typeof args[callbackIndex] === 'function';
      const passed = [...args];
      if (callbackIndex !== undefined && typeof args[callbackIndex] === 'function') {
        const callback = args[callbackIndex] as Callable;
        passed[callbackIndex] = function (this: unknown, ...values: any[]) {
          try { return Reflect.apply(callback, this, values); }
          finally { callbackCalled = true; if (returned && !promiseReturned) release(); }
        };
      }
      try {
        const result = Reflect.apply(fn, this, passed); returned = true;
        if (result && typeof result.then === 'function') {
          promiseReturned = true;
          // Fastify observes a normalised promise with the same settlement.
          return Promise.resolve(result).then(value => { release(); return value; }, error => { release(); throw error; });
        }
        if (!callbackStyle || callbackCalled) release();
        return result;
      } catch (error) { release(); throw error; }
    };
    Object.defineProperties(wrapped, { length: { value: fn.length }, name: { value: fn.name }, constructor: { value: fn.constructor } });
    this.wrappers.set(wrapped, { name, original: fn }); variants.set(name, wrapped); return wrapped;
  }

  install(server: FastifyInstance): void {
    if (this.installed.has(server)) return;
    const tracker = this, originalAddHook = server.addHook, originalNotFound = server.setNotFoundHandler;
    const wrapOptions = (options: Record<string, any>) => {
      if (typeof options.handler === 'function') options.handler = tracker.wrap('handler', options.handler);
      for (const name of Object.keys(hookCallbacks)) {
        if (Array.isArray(options[name])) options[name] = options[name].map((fn: unknown) => typeof fn === 'function' ? tracker.wrap(name, fn as Callable) : fn);
        else if (typeof options[name] === 'function') options[name] = tracker.wrap(name, options[name]);
      }
    };
    const wrapRoute = function (this: FastifyInstance, options: Record<string, any>) { wrapOptions(options); };
    Reflect.apply(originalAddHook, server, ['onRoute', wrapRoute]);
    const addHook = function (this: FastifyInstance, name: string, fn: unknown) {
      // Native addHook keeps its own synchronous/deferred validation order.
      const actual = Object.hasOwn(hookCallbacks, name) && typeof fn === 'function' ? tracker.wrap(name, fn as Callable, false) : fn;
      const result = Reflect.apply(originalAddHook, this, [name, actual]);
      // User/plugin onRoute hooks may replace a handler or add per-route hooks.
      // Reapply at the end, without altering the order of their own hooks.
      if (name === 'onRoute') Reflect.apply(originalAddHook, this, ['onRoute', wrapRoute]);
      return result;
    } as FastifyInstance['addHook'];
    const setNotFoundHandler = function (this: FastifyInstance, options: unknown, handler?: unknown) {
      if (typeof options === 'function') return Reflect.apply(originalNotFound, this, [tracker.wrap('handler', options as Callable)]);
      if (options && typeof options === 'object') { options = { ...options }; wrapOptions(options as Record<string, any>); }
      const actual = typeof handler === 'function' ? tracker.wrap('handler', handler as Callable) : handler;
      return Reflect.apply(originalNotFound, this, [options, actual]);
    } as FastifyInstance['setNotFoundHandler'];
    const installScope = (scope: FastifyInstance) => {
      if (tracker.installed.has(scope)) return;
      tracker.installed.add(scope); scope.addHook = addHook; scope.setNotFoundHandler = setNotFoundHandler;
    };
    installScope(server);
    // Native encapsulation hooks run before the child plugin body. Install own
    // methods too, so child fallback registration never depends on inheritance.
    Reflect.apply(originalAddHook, server, ['onRegister', installScope]);
  }
}

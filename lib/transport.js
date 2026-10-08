/**
 * Upstream transport for the OpenCode free lane.
 *
 * The plugin used `globalThis.fetch` (undici) for two reasons: streaming and
 * "no host bridge". Both are kept, but the connection is now ours:
 *
 *   - a proxy candidate (see lib/proxy.js) is dialed with CONNECT / SOCKS5 and
 *     the TLS session is layered inside the tunnel, so the exit node resolves
 *     `opencode.ai` remotely and a poisoned local DNS answer stops mattering;
 *   - when no proxy is in play, a direct attempt that fails at connect/TLS
 *     level is retried once against an address resolved through public DNS
 *     servers — the same trick that makes a poisoned answer survivable;
 *   - responses are streamed chunk by chunk: `body` is a plain node Readable
 *     that the loopback server pipes straight to the host, so SSE survives.
 *
 * The returned object mirrors just the slice of the fetch API this plugin
 * uses (`ok`, `status`, `headers.get`, `text`, `json`, `body`), which keeps
 * lib/zen.js and main.js untouched in shape.
 */

'use strict';

const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const { openTunnel } = require('./proxy.js');

const DEFAULT_PUBLIC_DNS = ['8.8.8.8', '9.9.9.9'];
const REQUEST_TIMEOUT_MS = 60_000;
const DNS_LOOKUP_TIMEOUT_MS = 5000;

/** Errors that mean "this route is dead" rather than "the server said no". */
const ROUTE_ERROR_CODES = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE', 'ETIMEDOUT',
  'ENOTFOUND', 'EAI_AGAIN', 'EPROXY', 'EPROTO', 'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_HAS_EXPIRED', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_SSL_WRONG_VERSION_NUMBER',
  'UND_ERR_CONNECT_TIMEOUT', 'EACCES', 'EHOSTDOWN',
]);

function routeFailure(error) {
  if (!error) return false;
  if (error.name === 'AbortError') return false;
  // Everything lib/proxy.js throws is a route problem, and it tags those errors
  // so even a proxy protocol error (bad CONNECT, unknown SOCKS reply) moves on
  // to the next candidate instead of failing the whole turn.
  if (error.tunnel === true) return true;
  if (error.code && ROUTE_ERROR_CODES.has(error.code)) return true;
  // A TLS failure surfaces as a plain Error with a message but no code.
  const message = String(error.message ?? '');
  return /socket hang up|timed? ?out|certificate|handshake|premature close/i.test(message);
}

/** `fetch failed` in disguise: keep the code and the message of the cause. */
function describeError(error) {
  if (!error) return 'unknown error';
  const parts = [];
  if (error.code) parts.push(error.code);
  if (error.message) parts.push(error.message);
  const cause = error.cause;
  if (cause && cause !== error) {
    const inner = [];
    if (cause.code) inner.push(cause.code);
    if (cause.message) inner.push(cause.message);
    if (inner.length > 0) parts.push(`(${inner.join(': ')})`);
  }
  return parts.length > 0 ? parts.join(' - ') : String(error);
}

/** An https.Agent that dials through a tunnel instead of straight out. */
class TunnelAgent extends https.Agent {
  constructor(tunnel, options) {
    super({ keepAlive: false, maxSockets: 1, ...options });
    this.tunnel = tunnel;
  }

  createConnection(options, callback) {
    Promise.resolve()
      .then(() => this.tunnel(options))
      .then((socket) => callback(null, socket), (error) => callback(error));
  }
}

/** Plain-http twin of TunnelAgent (a proxy may be asked for a http target). */
class PlainTunnelAgent extends http.Agent {
  constructor(tunnel, options) {
    super({ keepAlive: false, maxSockets: 1, ...options });
    this.tunnel = tunnel;
  }

  createConnection(options, callback) {
    Promise.resolve()
      .then(() => this.tunnel(options))
      .then((socket) => callback(null, socket), (error) => callback(error));
  }
}

function publicDnsLookup(host, servers) {
  return new Promise((resolve, reject) => {
    const resolver = new dns.Resolver();
    try {
      resolver.setServers(servers);
    } catch (error) {
      reject(error);
      return;
    }
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(Object.assign(new Error(`DNS lookup for ${host} timed out`), { code: 'ETIMEDOUT' }));
    }, DNS_LOOKUP_TIMEOUT_MS);
    if (timer.unref) timer.unref();
    resolver.resolve4(host, (error, addresses) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error || !addresses || addresses.length === 0) {
        reject(error ?? Object.assign(new Error(`no A record for ${host}`), { code: 'ENOTFOUND' }));
        return;
      }
      resolve(addresses);
    });
  });
}

function buildResponse(res, requestUrl) {
  const headers = {
    get(name) {
      const value = res.headers[String(name).toLowerCase()];
      return Array.isArray(value) ? value.join(', ') : value ?? null;
    },
    raw: res.headers,
  };
  return {
    ok: res.statusCode >= 200 && res.statusCode < 300,
    status: res.statusCode,
    statusText: res.statusMessage,
    url: requestUrl,
    headers,
    body: res,
    text() {
      return new Promise((resolve, reject) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        res.on('error', reject);
      });
    },
    async json() {
      const text = await this.text();
      return JSON.parse(text);
    },
  };
}

function defaultPortFor(protocol) {
  return protocol === 'https:' ? 443 : 80;
}

function singleRequest({ url, method, headers, body, signal, plan, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const target = url;
    const secure = target.protocol === 'https:';
    // `new URL(...).port` is '' whenever the scheme's default port is implied.
    const port = target.port ? Number(target.port) : defaultPortFor(target.protocol);
    const tunnel = async () => {
      if (plan.kind === 'proxy') {
        return openTunnel(plan.candidate, { host: target.hostname, port, tls: secure });
      }
      // Direct: optionally prefer an address resolved through public DNS.
      if (plan.pinnedAddress) {
        return openTunnel(
          { proxy: null },
          { host: plan.pinnedAddress, port, tls: secure },
          { servername: target.hostname },
        );
      }
      return openTunnel({ proxy: null }, { host: target.hostname, port, tls: secure });
    };

    const agent = secure ? new TunnelAgent(tunnel, {}) : new PlainTunnelAgent(tunnel, {});

    const options = {
      host: target.hostname,
      port,
      path: `${target.pathname}${target.search}`,
      method,
      headers,
      agent,
    };

    // The timer only guards connect + response headers; a stream that keeps
    // flowing must not be killed by it. Abort (client gone) still destroys the
    // request at any point.
    let timer = null;
    let settled = false;
    const request = (secure ? https : http).request(options, (res) => {
      settled = true;
      clearTimeout(timer);
      resolve(buildResponse(res, target.href));
    });
    const abortError = () => {
      const error = new Error('the request was aborted');
      error.name = 'AbortError';
      error.code = 'ABORT_ERR';
      return error;
    };
    const abort = () => request.destroy(abortError());

    // Register the error handler *before* anything can destroy the request:
    // an AbortSignal that fired while the candidates were still resolving used
    // to leave this promise unsettled and the destroyed request without an
    // 'error' listener, which Node reports as an uncaught exception.
    const settle = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', abort);
      reject(error);
    };
    request.on('error', settle);

    if (signal) {
      if (signal.aborted) {
        request.destroy();
        settle(abortError());
        return;
      }
      signal.addEventListener('abort', abort, { once: true });
    }

    timer = setTimeout(() => {
      if (settled) return;
      request.destroy(Object.assign(new Error(`upstream request timed out after ${timeoutMs}ms`), { code: 'ETIMEDOUT' }));
    }, timeoutMs ?? REQUEST_TIMEOUT_MS);
    if (timer.unref) timer.unref();

    if (body !== undefined && body !== null) request.write(body);
    request.end();
  });
}

/**
 * Build the transport used for both the chat/Responses lanes and the catalog
 * fetches. `resolveCandidates()` returns the ordered candidates for this
 * session (see lib/proxy.js); the list is re-resolved when it goes stale or
 * when every candidate has failed.
 */
function createUpstreamTransport({
  resolveCandidates,
  log = () => {},
  dnsFallback = true,
  publicDns = DEFAULT_PUBLIC_DNS,
  timeoutMs = REQUEST_TIMEOUT_MS,
  /** Re-resolve after this long, so a proxy that appears (or dies) later is
   * picked up without a plugin reload. */
  candidateTtlMs = 300_000,
} = {}) {
  let candidates = [];
  let resolvedAt = 0;
  let notes = [];
  /** Index of the candidate that last worked: one session keeps one route. */
  let stickyIndex = -1;
  let lastRoute = null;
  let lastError = null;
  const failures = new Map();
  const states = { requests: 0, retries: 0, dnsRetries: 0, resolutions: 0 };

  async function ensureCandidates(force = false) {
    const stale = Date.now() - resolvedAt > candidateTtlMs;
    if (!force && candidates.length > 0 && !stale) return candidates;
    const result = await resolveCandidates();
    candidates = result?.candidates ?? [{ proxy: null, source: 'direct (no proxy)' }];
    notes = result?.notes ?? [];
    resolvedAt = Date.now();
    states.resolutions += 1;
    stickyIndex = -1;
    return candidates;
  }

  function plansFor(candidate) {
    const plans = [{ kind: 'proxy', candidate }];
    if (!candidate.proxy && dnsFallback && publicDns.length > 0) {
      plans.push({ kind: 'direct-public-dns', candidate, needsLookup: true });
    }
    return plans;
  }

  async function requestWithPlan(urlObject, plan, { method, headers, body, signal }) {
    // A pinned-address plan resolves the name through public DNS first; the
    // TLS session still carries the real hostname (SNI + certificate host).
    if (plan.needsLookup) {
      const addresses = await publicDnsLookup(urlObject.hostname, publicDns);
      plan = { ...plan, kind: 'direct', pinnedAddress: addresses[0] };
    }
    return singleRequest({ url: urlObject, method, headers, body, signal, plan, agents: null, timeoutMs });
  }

  /** Ordered candidate walk: the sticky one first, then the rest. */
  function orderCandidates(list) {
    if (list.length === 0) return [];
    const start = stickyIndex >= 0 && stickyIndex < list.length ? stickyIndex : 0;
    const ordered = [];
    for (let offset = 0; offset < list.length; offset += 1) {
      ordered.push({ index: (start + offset) % list.length, candidate: list[(start + offset) % list.length] });
    }
    return ordered;
  }

  async function fetchUpstream(url, init = {}) {
    const method = (init.method ?? 'GET').toUpperCase();
    const body = init.body;
    const signal = init.signal;
    const headers = { ...(init.headers ?? {}) };
    const urlObject = new URL(url);
    const pool = await ensureCandidates();
    const attempts = [];

    for (const { index, candidate } of orderCandidates(pool)) {
      for (const basePlan of plansFor(candidate)) {
        states.requests += 1;
        try {
          const response = await requestWithPlan(urlObject, basePlan, { method, headers, body, signal });
          // Remember what worked: one session sticks to one route until the
          // list goes stale or the route starts failing.
          stickyIndex = index;
          lastRoute = {
            source: candidate.source,
            url: candidate.proxy?.url ?? null,
            via: basePlan.kind === 'direct-public-dns' ? 'direct + public DNS' : candidate.proxy ? 'proxy' : 'direct',
          };
          lastError = null;
          failures.delete(candidate.source);
          return response;
        } catch (error) {
          const description = describeError(error);
          attempts.push(`[${candidate.source}${basePlan.kind === 'direct-public-dns' ? ' + public DNS' : ''}] ${description}`);
          if (!routeFailure(error)) {
            // Not a routing problem (aborted, bad response): hand it to the caller.
            lastError = description;
            throw error;
          }
          if (basePlan.kind === 'direct-public-dns') states.dnsRetries += 1;
          else states.retries += 1;
          failures.set(candidate.source, (failures.get(candidate.source) ?? 0) + 1);
          log(`upstream route failed: ${candidate.source} -> ${description}`);
          if (signal?.aborted) throw error;
        }
      }
    }

    // Everything failed: drop the cache so the next call re-resolves (the
    // network may have changed) and report the whole walk.
    await ensureCandidates(true);
    stickyIndex = -1;
    lastError = attempts.join(' | ') || 'no route could be established';
    const error = new Error(lastError);
    error.code = 'ENOROUTE';
    throw error;
  }

  return {
    fetch: fetchUpstream,
    async state() {
      const pool = await ensureCandidates();
      return {
        candidates: pool.map((entry) => ({ source: entry.source, url: entry.proxy?.url ?? null })),
        active: lastRoute,
        notes,
        resolvedAt: new Date(resolvedAt).toISOString(),
        failures: Object.fromEntries(failures),
        lastError,
        counters: { ...states },
      };
    },
    async refresh() {
      await ensureCandidates(true);
      stickyIndex = -1;
    },
    invalidate() {
      stickyIndex = -1;
    },
    describeError,
    routeFailure,
  };
}

module.exports = {
  createUpstreamTransport,
  describeError,
  routeFailure,
  publicDnsLookup,
  ROUTE_ERROR_CODES,
  DEFAULT_PUBLIC_DNS,
};

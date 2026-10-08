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
const { Readable } = require('node:stream');
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

/** A proxy that fails this many dials in a row is walked last for a while. */
const PROXY_STRIKE_LIMIT = 3;
const PROXY_COOLDOWN_MS = 60_000;
/** Zen's country gate: only the egress country can fix it, not the body. */
const REGION_BLOCK_PATTERN = /RegionError|not available in your country/i;

/**
 * A response rebuilt from an already-consumed body. The region-block retry has
 * to read a 403 to recognise it; if the retry cannot do better, the caller must
 * still receive that same refusal.
 */
function syntheticResponse(status, contentType, text) {
  return {
    ok: false,
    status,
    statusText: '',
    headers: {
      get: (name) => (String(name).toLowerCase() === 'content-type' ? contentType : null),
      raw: { 'content-type': contentType },
    },
    body: Readable.from([Buffer.from(text, 'utf8')]),
    text: async () => text,
    json: async () => JSON.parse(text),
  };
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
  /**
   * The route that last worked. Only a *proxy* candidate becomes sticky: a
   * fallback to plain direct dialing is a stopgap for one request, not a
   * session decision. Pinning it would silently move every later request to
   * the local egress — and a country-gated model (muse-spark-* on the
   * Responses lane) then answers `RegionError: This model is not available in
   * your country`. Observed live: the local proxy timed out once, direct won,
   * the session stuck to direct, and every later Responses turn was refused.
   */
  let stickyIndex = -1;
  let lastRoute = null;
  let lastError = null;
  let directFallbackLogged = false;
  const failures = new Map();
  /** A proxy that keeps failing its dial is walked last for a while. */
  const proxyStrikes = new Map();
  const proxyCooldownUntil = new Map();
  const states = { requests: 0, retries: 0, dnsRetries: 0, resolutions: 0, regionRetries: 0 };

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

  function hasProxy(list) {
    return list.some((entry) => entry.proxy);
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
    return singleRequest({ url: urlObject, method, headers, body, signal, plan, timeoutMs });
  }

  /**
   * Ordered candidate walk: the sticky one first, then the rest, with proxies
   * that just failed a few dials pushed to the back so a dead local proxy does
   * not add its timeout to every request. They come back after the cooldown and
   * are still tried when nothing else works.
   */
  function orderCandidates(list) {
    if (list.length === 0) return [];
    const start = stickyIndex >= 0 && stickyIndex < list.length ? stickyIndex : 0;
    const ordered = [];
    for (let offset = 0; offset < list.length; offset += 1) {
      const index = (start + offset) % list.length;
      ordered.push({ index, candidate: list[index] });
    }
    const now = Date.now();
    const cooling = (entry) => Boolean(entry.candidate.proxy) && (proxyCooldownUntil.get(entry.candidate.source) ?? 0) > now;
    return [...ordered.filter((entry) => !cooling(entry)), ...ordered.filter(cooling)];
  }

  function noteProxyFailure(candidate) {
    if (!candidate.proxy) return;
    const strikes = (proxyStrikes.get(candidate.source) ?? 0) + 1;
    proxyStrikes.set(candidate.source, strikes);
    if (strikes >= PROXY_STRIKE_LIMIT) {
      proxyStrikes.set(candidate.source, 0);
      proxyCooldownUntil.set(candidate.source, Date.now() + PROXY_COOLDOWN_MS);
      log(`proxy ${candidate.proxy.url} failed ${PROXY_STRIKE_LIMIT} times in a row; trying it last for ${Math.round(PROXY_COOLDOWN_MS / 1000)}s`);
    }
  }

  function noteProxySuccess(candidate) {
    if (!candidate.proxy) return;
    proxyStrikes.delete(candidate.source);
    proxyCooldownUntil.delete(candidate.source);
    directFallbackLogged = false;
  }

  /**
   * Walk `list` in priority order. Resolves to `{ response }` for the first
   * candidate that produced an HTTP response, or `{ attempts }` when every
   * candidate failed at connect level.
   */
  async function walk({ urlObject, method, headers, body, signal }, list, { proxiesOnly = false } = {}) {
    const attempts = [];
    // Iterate the *unfiltered* list so a sticky index always names a candidate
    // in the caller's pool (a filtered walk would pin the wrong route).
    for (const { index, candidate } of orderCandidates(list)) {
      if (proxiesOnly && !candidate.proxy) continue;
      for (const basePlan of plansFor(candidate)) {
        states.requests += 1;
        try {
          const response = await requestWithPlan(urlObject, basePlan, { method, headers, body, signal });
          noteProxySuccess(candidate);
          // Only a real proxy becomes the session route (see above).
          stickyIndex = candidate.proxy ? index : -1;
          if (!candidate.proxy && hasProxy(list) && !directFallbackLogged) {
            directFallbackLogged = true;
            log('serving directly because no proxy candidate answered — country-gated models (muse-spark-*) will be refused from this egress');
          }
          lastRoute = {
            source: candidate.source,
            url: candidate.proxy?.url ?? null,
            via: basePlan.kind === 'direct-public-dns' ? 'direct + public DNS' : candidate.proxy ? 'proxy' : 'direct',
          };
          lastError = null;
          failures.delete(candidate.source);
          return { response, candidate, via: lastRoute.via };
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
          noteProxyFailure(candidate);
          log(`upstream route failed: ${candidate.source} -> ${description}`);
          if (signal?.aborted) throw error;
        }
      }
    }
    return { attempts };
  }

  async function fetchUpstream(url, init = {}) {
    const method = (init.method ?? 'GET').toUpperCase();
    const body = init.body;
    const signal = init.signal;
    const headers = { ...(init.headers ?? {}) };
    const urlObject = new URL(url);
    const pool = await ensureCandidates();

    const first = await walk({ urlObject, method, headers, body, signal }, pool);
    if (first.response) {
      // A country gate refuses the *local* egress; that is a routing fact, not
      // an answer. If the walk fell back to direct while proxies exist, retry
      // over the proxies before handing the refusal to the user.
      if (!first.response.ok
        && first.candidate.proxy === null
        && first.response.status === 403
        && hasProxy(pool)) {
        const contentType = first.response.headers.get('content-type') || 'application/json';
        const text = await first.response.text().catch(() => '');
        if (REGION_BLOCK_PATTERN.test(text)) {
          states.regionRetries += 1;
          log('upstream refused the direct route as region-blocked; retrying over the proxy');
          const second = await walk({ urlObject, method, headers, body, signal }, pool, { proxiesOnly: true });
          if (second.response) return second.response;
          log(`the proxy retry failed as well: ${second.attempts.join(' | ')}`);
        }
        return syntheticResponse(first.response.status, contentType, text);
      }
      return first.response;
    }
    // Everything failed: drop the cache so the next call re-resolves (the
    // network may have changed) and report the whole walk.
    await ensureCandidates(true);
    stickyIndex = -1;
    lastError = first.attempts.join(' | ') || 'no route could be established';
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

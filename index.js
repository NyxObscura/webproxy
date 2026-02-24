/**
 * Cloudflare Worker - Hardened Web Proxy
 * Production-ready, security-hardened, maintainable proxy implementation.
 */

// ---------------------------------------------------------------------------
// Configuration - single source of truth
// ---------------------------------------------------------------------------
const CONFIG = Object.freeze({
  proxyDomains: [
  'webproxy.obscuraworks.org',
  'webproxy.ahmadmuwafik337.workers.dev',
],
  separator: '------',
  homepage: true,
  allowedDomains: [], // empty = allow all (except SSRF-blocked targets)

  browserEmulation: Object.freeze({
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    acceptLanguage: 'en-US,en;q=0.9',
    acceptEncoding: 'gzip, deflate, br',
    secFetchDest: 'document',
    secFetchMode: 'navigate',
    secFetchSite: 'none',
    secFetchUser: '?1',
    upgradeInsecureRequests: '1',
  }),

  fallback: Object.freeze({
    enabled: true,
    autoReload: true,
  }),

  specialSites: Object.freeze({
    wikipedia: Object.freeze({
      enabled: true,
      domains: ['wikipedia.org', 'wikimedia.org', 'mediawiki.org'],
    }),
  }),

  // SSRF protection: blocked hostnames, suffixes, and IPv4 prefixes
  ssrf: Object.freeze({
    blockedHosts: new Set([
      'localhost',
      'metadata.google.internal',
      '169.254.169.254', // AWS/GCP/Azure metadata
    ]),
    blockedSuffixes: ['.local', '.internal', '.localhost'],
    // Blocked IPv4 prefix strings (cheap prefix check before full parse)
    blockedIPv4Prefixes: ['10.', '172.', '192.168.', '127.', '0.', '100.64.'],
  }),

  // Headers that are unsafe to forward to target or to reflect to client
  forbiddenRequestHeaders: new Set([
    'cf-connecting-ip',
    'cf-ipcountry',
    'cf-ray',
    'cf-visitor',
    'cf-worker',
    'x-forwarded-for',
    'x-real-ip',
    'x-forwarded-host',
    'x-forwarded-proto',
    'fly-forwarded-port',
    'fly-request-id',
  ]),

  forbiddenResponseHeaders: new Set([
    'content-security-policy',
    'content-security-policy-report-only',
    'x-frame-options',
    'x-content-type-options',
    'strict-transport-security',
    'expect-ct',
    'clear-site-data',
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'permissions-policy',
    'report-to',
    'nel',
  ]),

  // Pass-through request headers (allowlist approach)
  passthroughRequestHeaders: [
    'cookie',
    'range',
    'if-none-match',
    'if-modified-since',
    'if-match',
    'if-unmodified-since',
    'content-type',
    'content-length',
    'accept',
    'accept-charset',
    'cache-control',
    'pragma',
  ],
})

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = safeParseURL(request.url)
  if (!url) return plainResponse('Bad request URL', 400)

  // Handle CORS preflight so proxied XHR/fetch calls work from the browser
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(),
    })
  }

  const isProxyHost = CONFIG.proxyDomains.includes(url.host)

  // Homepage - only on exact root with no query string
  if (isProxyHost && url.pathname === '/' && !url.search && CONFIG.homepage) {
    return buildHomePage(url.host)
  }

  // Resolve the target URL from the incoming request
  let targetURL
  try {
    targetURL = resolveTargetURL(request, url, isProxyHost)
  } catch (err) {
    return plainResponse(`URL resolution error: ${err.message}`, 400)
  }

  if (!targetURL) {
    return plainResponse('Could not determine target URL', 400)
  }

  // SSRF guard
  const ssrfError = checkSSRF(targetURL)
  if (ssrfError) return plainResponse(`Blocked: ${ssrfError}`, 403)

  // Domain allowlist
  if (CONFIG.allowedDomains.length > 0) {
    const allowed = CONFIG.allowedDomains.some(
      d => targetURL.hostname === d || targetURL.hostname.endsWith(`.${d}`)
    )
    if (!allowed) return plainResponse('Domain not in allowlist', 403)
  }

  // Only proxy http / https
  if (targetURL.protocol !== 'http:' && targetURL.protocol !== 'https:') {
    return plainResponse('Only http and https targets are supported', 400)
  }

  // Build and send the proxied request
  let proxyRequest
  try {
    proxyRequest = createProxiedRequest(request, targetURL)
  } catch (err) {
    return plainResponse(`Request construction error: ${err.message}`, 400)
  }

  let response
  try {
    response = await fetch(proxyRequest)
  } catch (err) {
    return buildErrorPage(targetURL, err.message)
  }

  return buildProxyResponse(request, url, targetURL, response)
}

// ---------------------------------------------------------------------------
// URL resolution logic
// ---------------------------------------------------------------------------

/**
 * Determine the real target URL from the incoming proxy request.
 * All path-decoding logic lives here to avoid duplication.
 */
function resolveTargetURL(request, url, isProxyHost) {
  if (!isProxyHost) {
    // Non-proxy host: the worker itself IS the target (passthrough mode)
    return url
  }

  const sep = CONFIG.separator
  const rawPath = url.pathname.slice(1) // strip leading /

  // Strip separator prefix if present
  const innerPath = rawPath.startsWith(sep) ? rawPath.slice(sep.length) : rawPath

  // Case 1: explicit absolute URL embedded in path
  if (innerPath.startsWith('http://') || innerPath.startsWith('https://')) {
    // Preserve any query string from the proxy request
    const t = safeParseURL(innerPath)
    if (!t) throw new Error('Malformed embedded URL')
    if (url.search && !t.search) {
      t.search = url.search
    }
    return t
  }

  // Case 2: /proxy?url= format
  if (url.pathname === '/proxy' && url.searchParams.has('url')) {
    const t = safeParseURL(url.searchParams.get('url'))
    if (!t) throw new Error('Malformed url parameter')
    return t
  }

  // Case 3: non-empty relative path - try to resolve against Referer base
  if (innerPath) {
    const refBase = extractRefererBase(request, url)
    if (refBase) {
      const resolved = safeResolveURL(innerPath, refBase)
      if (resolved) return resolved
    }

    // No dots and no query string => treat as search keyword
    if (!innerPath.includes('.') && !url.search) {
      return safeParseURL('https://duckduckgo.com/?q=' + encodeURIComponent(innerPath))
    }

    // No dots but has query string => keyword + extra params
    if (!innerPath.includes('.')) {
      const q = encodeURIComponent(innerPath)
      const extra = url.search ? '&' + url.search.slice(1) : ''
      return safeParseURL('https://duckduckgo.com/?q=' + q + extra)
    }

    // Has 'q' query param => probably forwarded search
    if (url.searchParams.has('q')) {
      const ddg = new URL('https://duckduckgo.com/')
      url.searchParams.forEach((v, k) => ddg.searchParams.append(k, v))
      return ddg
    }

    // Looks like a bare domain - add scheme
    const withScheme = safeParseURL('https://' + innerPath)
    if (withScheme) return withScheme

    throw new Error('Cannot resolve target URL from path')
  }

  // Case 4: empty path but has query string (e.g. /?q=foo from proxied DuckDuckGo)
  if (url.search) {
    // Try to reconstruct from Referer before falling back to DDG
    const refBase = extractRefererBase(request, url)
    if (refBase) {
      const t = safeParseURL(refBase.origin + url.search)
      if (t) return t
    }

    if (url.searchParams.has('q')) {
      const ddg = new URL('https://duckduckgo.com/')
      url.searchParams.forEach((v, k) => ddg.searchParams.append(k, v))
      return ddg
    }
  }

  return null
}

/**
 * Extract the base URL of the currently proxied site from the Referer header.
 * Returns a URL object representing the origin + path of the real target, or null.
 */
function extractRefererBase(request, proxyURL) {
  const referer = request.headers.get('Referer') || ''
  if (!referer) return null

  const expectedPrefix = `https://${proxyURL.host}/`
  if (!referer.startsWith(expectedPrefix)) return null

  let inner = referer.slice(expectedPrefix.length)
  if (inner.startsWith(CONFIG.separator)) inner = inner.slice(CONFIG.separator.length)

  return safeParseURL(inner)
}

// ---------------------------------------------------------------------------
// Proxied request construction
// ---------------------------------------------------------------------------

/**
 * Build the outbound Request to the target server.
 * Applies browser emulation headers, sanitizes incoming headers, and
 * sets correct Host/Origin/Referer for the target site.
 */
function createProxiedRequest(originalRequest, targetURL) {
  const headers = sanitizeRequestHeaders(originalRequest.headers, targetURL)

  // Body: only for methods that carry one; do NOT clone to avoid stream bugs
  const hasBody = originalRequest.method !== 'GET' && originalRequest.method !== 'HEAD'

  return new Request(targetURL.href, {
    method: originalRequest.method,
    headers,
    body: hasBody ? originalRequest.body : null,
    redirect: 'manual',
    // duplex required when body is a ReadableStream in newer runtimes
    ...(hasBody && originalRequest.body ? { duplex: 'half' } : {}),
  })
}

/**
 * Build a sanitized Headers object for the outbound request.
 * Uses an allowlist for forwarded client headers, adds browser emulation
 * headers, and removes anything that could leak worker internals or enable
 * header smuggling.
 */
function sanitizeRequestHeaders(incoming, targetURL) {
  const out = new Headers()

  // Pass through safe client headers
  for (const name of CONFIG.passthroughRequestHeaders) {
    const val = incoming.get(name)
    if (val !== null) {
      // Skip content-length; let the runtime set it correctly
      if (name === 'content-length') continue
      out.set(name, val)
    }
  }

  // Explicitly drop forbidden headers (belt-and-suspenders)
  for (const name of CONFIG.forbiddenRequestHeaders) {
    out.delete(name)
  }

  // Browser emulation
  const be = CONFIG.browserEmulation
  out.set('User-Agent', be.userAgent)
  out.set('Accept-Language', be.acceptLanguage)
  out.set('Accept-Encoding', be.acceptEncoding)
  out.set('Upgrade-Insecure-Requests', be.upgradeInsecureRequests)
  out.set('Sec-Fetch-Dest', be.secFetchDest)
  out.set('Sec-Fetch-Mode', be.secFetchMode)
  out.set('Sec-Fetch-Site', be.secFetchSite)
  out.set('Sec-Fetch-User', be.secFetchUser)

  // Target-correct Host / Origin / Referer
  out.set('Host', targetURL.host)
  out.set('Origin', targetURL.origin)
  out.set('Referer', targetURL.href)

  // Forward XHR marker if present
  if (incoming.get('X-Requested-With') === 'XMLHttpRequest') {
    out.set('X-Requested-With', 'XMLHttpRequest')
  }

  return out
}

// ---------------------------------------------------------------------------
// Proxied response construction
// ---------------------------------------------------------------------------

/**
 * Process the raw fetch response: rewrite redirect locations, strip/add
 * security headers, then rewrite content as appropriate for content type.
 */
function buildProxyResponse(originalRequest, proxyURL, targetURL, response) {
  const respHeaders = sanitizeResponseHeaders(response.headers)

  // Rewrite redirect Location header
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = response.headers.get('Location')
    if (location) {
      const rewritten = rewriteRedirectLocation(location, targetURL, proxyURL.host)
      if (rewritten) respHeaders.set('Location', rewritten)
    }
  }

  // CORS - allow browser to use proxied resources
  respHeaders.set('Access-Control-Allow-Origin', '*')
  respHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH')
  respHeaders.set('Access-Control-Allow-Headers', '*')
  // Note: ACAC true + ACAO * is technically invalid but maximally permissive for proxy use
  respHeaders.set('Access-Control-Allow-Credentials', 'true')

  const contentType = (response.headers.get('Content-Type') || '').toLowerCase()
  const currentProxyDomain = proxyURL.host

  // HTML rewriting via HTMLRewriter (streaming - no buffering)
  if (contentType.includes('text/html') || contentType.includes('application/xhtml+xml')) {
    const isWiki = isWikipediaSite(targetURL)
    const rewriter = buildHTMLRewriter(targetURL, currentProxyDomain, isWiki)
    const rewritten = rewriter.transform(
      new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: respHeaders,
      })
    )
    return rewritten
  }

  // CSS rewriting (must buffer - no streaming regex API in Workers)
  if (contentType.includes('text/css') || contentType.includes('application/x-stylesheet')) {
    return rewriteTextResponse(response, respHeaders, text =>
      rewriteCSS(text, targetURL, currentProxyDomain)
    )
  }

  // JavaScript rewriting (buffered, best-effort)
  if (
    contentType.includes('application/javascript') ||
    contentType.includes('text/javascript') ||
    contentType.includes('application/x-javascript')
  ) {
    return rewriteTextResponse(response, respHeaders, text =>
      rewriteJavaScript(text, targetURL, currentProxyDomain)
    )
  }

  // All other content types: stream through unchanged
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: respHeaders,
  })
}

/**
 * Buffer a text response, transform it, and return a new Response.
 * Removes Content-Length since the rewritten body may differ in size.
 */
async function rewriteTextResponse(response, headers, transformFn) {
  const text = await response.text()
  const rewritten = transformFn(text)
  headers.delete('content-length') // length may have changed
  return new Response(rewritten, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

/**
 * Strip security/framing headers from response, keep the rest.
 */
function sanitizeResponseHeaders(incoming) {
  const out = new Headers()
  for (const [name, value] of incoming.entries()) {
    const lower = name.toLowerCase()
    if (CONFIG.forbiddenResponseHeaders.has(lower)) continue
    // Skip content-length; we may rewrite the body
    if (lower === 'content-length') continue
    out.append(name, value)
  }
  return out
}

/**
 * Rewrite a redirect Location to route through the proxy.
 */
function rewriteRedirectLocation(location, targetURL, proxyDomain) {
  const resolved = safeResolveURL(location, targetURL)
  if (!resolved) return null
  return buildProxyURL(resolved.href, proxyDomain)
}

// ---------------------------------------------------------------------------
// HTML rewriting
// ---------------------------------------------------------------------------

function buildHTMLRewriter(targetURL, proxyDomain, isWiki) {
  let rw = new HTMLRewriter()
    .on('a[href]',          new LinkRewriter(targetURL, 'href',   proxyDomain))
    .on('form[action]',     new LinkRewriter(targetURL, 'action', proxyDomain))
    .on('img[src]',         new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('img[srcset]',      new SrcsetRewriter(targetURL, proxyDomain))
    .on('source[srcset]',   new SrcsetRewriter(targetURL, proxyDomain))
    .on('source[src]',      new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('link[href]',       new LinkRewriter(targetURL, 'href',   proxyDomain))
    .on('script[src]',      new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('iframe[src]',      new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('video[src]',       new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('audio[src]',       new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('embed[src]',       new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('object[data]',     new LinkRewriter(targetURL, 'data',   proxyDomain))
    .on('track[src]',       new LinkRewriter(targetURL, 'src',    proxyDomain))
    .on('meta[content]',    new MetaContentRewriter(targetURL, proxyDomain))
    .on('base[href]',       new BaseTagRewriter(targetURL, proxyDomain))
    .on('*[style]',         new StyleAttributeRewriter(targetURL, proxyDomain))

  if (isWiki) {
    rw = rw
      .on('img[data-src]', new LinkRewriter(targetURL, 'data-src', proxyDomain))
      .on('style',         new StyleElementRewriter(targetURL, proxyDomain))
  }

  if (CONFIG.fallback.enabled && CONFIG.fallback.autoReload) {
    rw = rw.on('head', new HeadRewriter(proxyDomain))
  }

  return rw
}

// ---------------------------------------------------------------------------
// HTMLRewriter element handlers
// ---------------------------------------------------------------------------

class LinkRewriter {
  constructor(baseURL, attr, proxyDomain) {
    this.baseURL = baseURL
    this.attr = attr
    this.proxyDomain = proxyDomain
  }

  element(el) {
    const val = el.getAttribute(this.attr)
    if (!val) return
    if (isBypassURL(val)) return
    if (isAlreadyProxied(val, this.proxyDomain)) return

    const absolute = safeResolveURL(normalizeProtocolRelative(val, this.baseURL), this.baseURL)
    if (!absolute) return

    // WS/WSS: rewrite to proxied https equivalent (browser will upgrade)
    const finalURL = rewriteWebSocketURL(absolute) || absolute

    el.setAttribute(this.attr, buildProxyURL(finalURL.href, this.proxyDomain))

    // Image error fallback via data attribute (no inline JS injection)
    if (this.attr === 'src' && el.tagName === 'img') {
      el.setAttribute('data-original-src', finalURL.href)
    }
  }
}

class SrcsetRewriter {
  constructor(baseURL, proxyDomain) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
  }

  element(el) {
    const srcset = el.getAttribute('srcset')
    if (!srcset) return

    const rewritten = srcset
      .split(/,\s+/)
      .map(part => {
        const [rawURL, descriptor] = part.trim().split(/\s+/, 2)
        if (!rawURL || isBypassURL(rawURL) || isAlreadyProxied(rawURL, this.proxyDomain)) {
          return part
        }
        const abs = safeResolveURL(normalizeProtocolRelative(rawURL, this.baseURL), this.baseURL)
        if (!abs) return part
        const proxied = buildProxyURL(abs.href, this.proxyDomain)
        return descriptor ? `${proxied} ${descriptor}` : proxied
      })
      .join(', ')

    el.setAttribute('srcset', rewritten)
  }
}

class MetaContentRewriter {
  constructor(baseURL, proxyDomain) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
  }

  element(el) {
    const httpEquiv = (el.getAttribute('http-equiv') || '').toLowerCase()
    const content = el.getAttribute('content')
    if (!content) return

    // meta refresh
    if (httpEquiv === 'refresh') {
      const match = content.match(/^(\d+)\s*;?\s*url=(.+)$/i)
      if (match) {
        const abs = safeResolveURL(match[2].trim(), this.baseURL)
        if (abs) {
          el.setAttribute(
            'content',
            `${match[1]};url=${buildProxyURL(abs.href, this.proxyDomain)}`
          )
        }
      }
      return
    }

    // Open Graph / Twitter image and URL meta tags
    const prop = (el.getAttribute('property') || el.getAttribute('name') || '').toLowerCase()
    if (
      prop === 'og:image' ||
      prop === 'og:url' ||
      prop === 'twitter:image' ||
      prop === 'twitter:url'
    ) {
      const abs = safeResolveURL(content, this.baseURL)
      if (abs) el.setAttribute('content', buildProxyURL(abs.href, this.proxyDomain))
    }
  }
}

class BaseTagRewriter {
  constructor(baseURL, proxyDomain) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
  }

  element(el) {
    const href = el.getAttribute('href')
    if (!href) return
    const abs = safeResolveURL(href, this.baseURL)
    if (abs) el.setAttribute('href', buildProxyURL(abs.href, this.proxyDomain))
  }
}

class StyleAttributeRewriter {
  constructor(baseURL, proxyDomain) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
  }

  element(el) {
    const style = el.getAttribute('style')
    if (!style) return
    el.setAttribute('style', rewriteCSS(style, this.baseURL, this.proxyDomain))
  }
}

class StyleElementRewriter {
  constructor(baseURL, proxyDomain) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
  }

  text(chunk) {
    chunk.replace(rewriteCSS(chunk.text, this.baseURL, this.proxyDomain))
  }
}

/**
 * Inject a minimal, sanitized script into <head> to handle image fallbacks
 * and block open redirects in _blank links.
 * All strings are statically constructed - no user input is reflected.
 */
class HeadRewriter {
  constructor(proxyDomain) {
    this.proxyDomain = proxyDomain
  }

  element(el) {
    // Escape the proxy domain for safe inline use (it comes from CONFIG, not user input,
    // but we escape anyway as defence-in-depth)
    const safeDomain = escapeForJS(this.proxyDomain)
    const sep = escapeForJS(CONFIG.separator)

    el.append(
      `<script>
(function(){
  'use strict';
  var PROXY = 'https://${safeDomain}';
  var SEP   = '${sep}';
  function proxyHref(href){
    if(!href||href.startsWith('data:')||href.startsWith('javascript:')) return href;
    if(href.startsWith(PROXY+'/')) return href;
    try{ return PROXY+'/'+SEP+new URL(href,location.href).href; }catch(e){ return href; }
  }
  document.addEventListener('DOMContentLoaded',function(){
    // Image error fallback
    document.querySelectorAll('img[data-original-src]').forEach(function(img){
      img.onerror=function(){
        this.onerror=null;
        var orig=this.dataset.originalSrc;
        if(orig&&this.src!==orig) this.src=orig;
      };
    });
    // Wikipedia lazy images
    if(document.querySelector('body.mediawiki')){
      document.querySelectorAll('img[data-src]').forEach(function(img){
        if(!img.src&&img.dataset.src) img.src=proxyHref(img.dataset.src);
      });
    }
  });
})();
</script>`,
      { html: true }
    )
  }
}

// ---------------------------------------------------------------------------
// CSS rewriting
// ---------------------------------------------------------------------------

function rewriteCSS(css, baseURL, proxyDomain) {
  if (!css) return css

  // Rewrite @import url(...) and @import "..."
  css = css.replace(
    /@import\s+(?:url\(\s*(['"]?)([^'")]+)\1\s*\)|(['"])([^'"]+)\3)/g,
    (match, _q1, urlFromFunc, _q2, urlFromStr) => {
      const raw = urlFromFunc || urlFromStr
      if (!raw || isBypassURL(raw) || isAlreadyProxied(raw, proxyDomain)) return match
      const abs = safeResolveURL(normalizeProtocolRelative(raw, baseURL), baseURL)
      if (!abs) return match
      return match.replace(raw, buildProxyURL(abs.href, proxyDomain))
    }
  )

  // Rewrite url(...) everywhere
  css = css.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/g,
    (match, quote, raw) => {
      if (!raw || isBypassURL(raw) || isAlreadyProxied(raw, proxyDomain)) return match
      const abs = safeResolveURL(normalizeProtocolRelative(raw, baseURL), baseURL)
      if (!abs) return match
      return `url(${quote}${buildProxyURL(abs.href, proxyDomain)}${quote})`
    }
  )

  return css
}

// ---------------------------------------------------------------------------
// JavaScript rewriting (best-effort, no full parse)
// ---------------------------------------------------------------------------

function rewriteJavaScript(js, baseURL, proxyDomain) {
  if (!js) return js

  // Only rewrite absolute http(s) URLs embedded in string literals.
  // We deliberately avoid touching relative paths or complex expressions
  // because regex-based JS rewriting without a real parser causes breakage.
  return js.replace(/(["'])(https?:\/\/[^"']+)\1/g, (match, quote, rawURL) => {
    if (isAlreadyProxied(rawURL, proxyDomain)) return match
    // Validate it looks like a URL
    const parsed = safeParseURL(rawURL)
    if (!parsed) return match
    return `${quote}${buildProxyURL(rawURL, proxyDomain)}${quote}`
  })
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

function checkSSRF(targetURL) {
  const hostname = targetURL.hostname.toLowerCase()

  if (CONFIG.ssrf.blockedHosts.has(hostname)) {
    return `Blocked host: ${hostname}`
  }

  for (const suffix of CONFIG.ssrf.blockedSuffixes) {
    if (hostname.endsWith(suffix)) return `Blocked host suffix: ${suffix}`
  }

  // Reject bare IPv4 in private/link-local ranges
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    for (const prefix of CONFIG.ssrf.blockedIPv4Prefixes) {
      if (hostname.startsWith(prefix)) return `Blocked IP prefix: ${prefix}`
    }
    // Also block 172.16.0.0/12 which prefix "172." alone does not fully cover
    const parts = hostname.split('.').map(Number)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
      return `Blocked private IP: ${hostname}`
    }
  }

  // Block IPv6 loopback / link-local (bracket form stripped by URL parser)
  if (hostname === '[::1]' || hostname === '::1') return 'Blocked IPv6 loopback'

  return null // OK
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/** Safely parse a URL string; return null instead of throwing. */
function safeParseURL(str) {
  if (!str) return null
  try {
    return new URL(str)
  } catch {
    return null
  }
}

/** Safely resolve a relative URL against a base; return null on failure. */
function safeResolveURL(href, base) {
  if (!href) return null
  try {
    return new URL(href, base)
  } catch {
    return null
  }
}

/** Convert protocol-relative //example.com to https://example.com */
function normalizeProtocolRelative(href, baseURL) {
  if (href.startsWith('//')) return baseURL.protocol + href
  return href
}

/**
 * Build the final proxy URL for a given absolute target href.
 * Format: https://<proxyDomain>/<separator><targetHref>
 */
function buildProxyURL(targetHref, proxyDomain) {
  return `https://${proxyDomain}/${CONFIG.separator}${targetHref}`
}

/** Return true for URL schemes that must never be rewritten. */
function isBypassURL(href) {
  return (
    href.startsWith('data:') ||
    href.startsWith('blob:') ||
    href.startsWith('javascript:') ||
    href.startsWith('mailto:') ||
    href.startsWith('tel:') ||
    href.startsWith('#')
  )
}

/** Return true if a URL is already routed through this proxy. */
function isAlreadyProxied(href, proxyDomain) {
  return href.startsWith(`https://${proxyDomain}/`)
}

/** Rewrite ws:// -> http:// and wss:// -> https:// for proxy passthrough. */
function rewriteWebSocketURL(urlObj) {
  if (urlObj.protocol === 'ws:') return safeParseURL('http:' + urlObj.href.slice(3))
  if (urlObj.protocol === 'wss:') return safeParseURL('https:' + urlObj.href.slice(4))
  return null
}

function isWikipediaSite(targetURL) {
  if (!CONFIG.specialSites.wikipedia.enabled) return false
  return CONFIG.specialSites.wikipedia.domains.some(d => targetURL.hostname.endsWith(d))
}

/** Standard CORS headers for preflight responses. */
function corsHeaders() {
  return new Headers({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Max-Age': '86400',
  })
}

function plainResponse(message, status) {
  return new Response(message, {
    status,
    headers: { 'Content-Type': 'text/plain;charset=UTF-8', ...Object.fromEntries(corsHeaders()) },
  })
}

/**
 * Escape a string for safe embedding inside a JS string literal.
 * Covers the characters that could break out of the literal or start tags.
 */
function escapeForJS(str) {
  return str
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/</g, '\\x3C')
    .replace(/>/g, '\\x3E')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
}

// ---------------------------------------------------------------------------
// Error page
// ---------------------------------------------------------------------------

function buildErrorPage(targetURL, errorMessage) {
  // Escape all user-derived / external values before inserting into HTML
  const safeError = escapeHTML(errorMessage || 'Unknown error')
  const safeHref = escapeHTML(targetURL.href)
  const safeTime = new Date().toISOString()

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy Error</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    line-height:1.6;color:#333;max-width:800px;margin:0 auto;padding:20px}
    .error{background:#f8d7da;color:#721c24;padding:15px;border-radius:4px;margin-bottom:20px}
    .info{background:#d4edda;color:#155724;padding:15px;border-radius:4px;margin-bottom:20px}
    h1{color:#d63031}
    a.btn{display:inline-block;margin-top:10px;color:#fff;background:#17a2b8;
    padding:8px 16px;text-decoration:none;border-radius:4px}
    a.btn:hover{background:#138496}
    .details{background:#f8f9fa;padding:15px;border-radius:4px;margin-top:20px;
    font-family:monospace;white-space:pre-wrap}
  </style>
</head>
<body>
  <h1>Proxy Request Failed</h1>
  <div class="error"><strong>Error:</strong> ${safeError}</div>
  <div class="info">
    <p>The proxy could not reach the requested resource. You may try directly:</p>
    <a class="btn" href="${safeHref}" target="_blank" rel="noopener noreferrer">Open ${safeHref} directly</a>
  </div>
  <div class="details">Request URL: ${safeHref}
Time: ${safeTime}</div>
</body>
</html>`

  return new Response(html, {
    status: 502,
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Access-Control-Allow-Origin': '*',
    },
  })
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// ---------------------------------------------------------------------------
// Homepage
// ---------------------------------------------------------------------------

function buildHomePage(proxyDomain) {
  const sep = CONFIG.separator

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ObscuraProxy — Private Web Access</title>
  <meta name="description" content="Browse the web privately through ObscuraWorks' secure proxy infrastructure, powered by Cloudflare.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;500&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;1,9..40,300&display=swap" rel="stylesheet">
  <style>
    :root {
      --black:    #0a0a0a;
      --white:    #fafafa;
      --gray-100: #f4f4f5;
      --gray-200: #e4e4e7;
      --gray-400: #a1a1aa;
      --gray-600: #52525b;
      --gray-800: #27272a;
      --accent:   #18181b;
      --radius:   6px;
      --font-sans: 'DM Sans', sans-serif;
      --font-mono: 'Geist Mono', monospace;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    html { scroll-behavior: smooth; }

    body {
      font-family: var(--font-sans);
      background: var(--white);
      color: var(--black);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }

    /* ---- NAV ---- */
    nav {
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 100;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 32px;
      height: 56px;
      background: rgba(250,250,250,0.85);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--gray-200);
    }

    .nav-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
    }

    .nav-logo {
      width: 24px; height: 24px;
      background: var(--black);
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .nav-logo svg { width: 14px; height: 14px; fill: var(--white); }

    .nav-name {
      font-size: 14px;
      font-weight: 500;
      color: var(--black);
      letter-spacing: -0.01em;
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 24px;
      list-style: none;
    }

    .nav-links a {
      font-size: 13px;
      color: var(--gray-600);
      text-decoration: none;
      transition: color 0.15s;
      font-weight: 400;
    }

    .nav-links a:hover { color: var(--black); }

    .nav-cta {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .btn-ghost {
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 500;
      color: var(--gray-600);
      background: none;
      border: none;
      cursor: pointer;
      padding: 6px 12px;
      border-radius: var(--radius);
      transition: color 0.15s, background 0.15s;
      text-decoration: none;
    }
    .btn-ghost:hover { color: var(--black); background: var(--gray-100); }

    .btn-primary {
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 500;
      color: var(--white);
      background: var(--black);
      border: 1px solid var(--black);
      padding: 6px 14px;
      border-radius: var(--radius);
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s;
      text-decoration: none;
    }
    .btn-primary:hover { background: var(--gray-800); border-color: var(--gray-800); }

    /* ---- HERO ---- */
    main {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding-top: 160px;
      padding-bottom: 120px;
      padding-left: 24px;
      padding-right: 24px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      font-family: var(--font-mono);
      font-weight: 500;
      color: var(--gray-600);
      background: var(--gray-100);
      border: 1px solid var(--gray-200);
      padding: 4px 10px;
      border-radius: 100px;
      margin-bottom: 32px;
      letter-spacing: 0.02em;
    }

    .badge-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      background: #22c55e;
      box-shadow: 0 0 0 2px rgba(34,197,94,0.2);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { box-shadow: 0 0 0 2px rgba(34,197,94,0.2); }
      50% { box-shadow: 0 0 0 4px rgba(34,197,94,0.1); }
    }

    h1 {
      font-size: clamp(36px, 6vw, 64px);
      font-weight: 300;
      letter-spacing: -0.04em;
      line-height: 1.1;
      text-align: center;
      color: var(--black);
      max-width: 640px;
      margin-bottom: 20px;
    }

    h1 strong {
      font-weight: 500;
    }

    .hero-sub {
      font-size: 16px;
      font-weight: 300;
      color: var(--gray-600);
      text-align: center;
      max-width: 420px;
      line-height: 1.65;
      margin-bottom: 48px;
    }

    /* ---- SEARCH BOX ---- */
    .search-wrap {
      width: 100%;
      max-width: 560px;
      margin-bottom: 16px;
    }

    .search-box {
      display: flex;
      align-items: center;
      background: var(--white);
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      overflow: hidden;
      transition: border-color 0.15s, box-shadow 0.15s;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }

    .search-box:focus-within {
      border-color: var(--black);
      box-shadow: 0 0 0 3px rgba(0,0,0,0.06);
    }

    .search-icon {
      padding: 0 14px;
      color: var(--gray-400);
      display: flex;
      align-items: center;
      flex-shrink: 0;
    }

    .search-icon svg { width: 16px; height: 16px; }

    #urlInput {
      flex: 1;
      border: none;
      outline: none;
      font-family: var(--font-mono);
      font-size: 13.5px;
      font-weight: 400;
      color: var(--black);
      background: transparent;
      padding: 14px 0;
      letter-spacing: -0.01em;
    }

    #urlInput::placeholder {
      color: var(--gray-400);
      font-family: var(--font-sans);
      font-size: 14px;
      font-weight: 300;
      letter-spacing: 0;
    }

    #goBtn {
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 500;
      color: var(--white);
      background: var(--black);
      border: none;
      padding: 10px 20px;
      margin: 6px;
      border-radius: 4px;
      cursor: pointer;
      transition: background 0.15s;
      white-space: nowrap;
      flex-shrink: 0;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    #goBtn:hover { background: var(--gray-800); }

    #goBtn svg { width: 14px; height: 14px; }

    .search-hint {
      font-size: 12px;
      color: var(--gray-400);
      text-align: center;
      font-weight: 400;
    }

    /* ---- QUICK LINKS ---- */
    .quick-links {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px;
      margin-top: 32px;
      max-width: 560px;
    }

    .quick-link {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 12px;
      font-weight: 400;
      color: var(--gray-600);
      background: var(--gray-100);
      border: 1px solid var(--gray-200);
      padding: 5px 12px;
      border-radius: 100px;
      text-decoration: none;
      transition: border-color 0.15s, color 0.15s, background 0.15s;
      font-family: var(--font-mono);
      letter-spacing: -0.01em;
    }

    .quick-link:hover {
      border-color: var(--black);
      color: var(--black);
      background: var(--white);
    }

    /* ---- DIVIDER / FEATURES ---- */
    .features-section {
      width: 100%;
      max-width: 880px;
      margin: 96px auto 0;
      border-top: 1px solid var(--gray-200);
      padding-top: 64px;
    }

    .features-label {
      font-size: 11px;
      font-weight: 500;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--gray-400);
      text-align: center;
      margin-bottom: 40px;
      font-family: var(--font-mono);
    }

    .features-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1px;
      background: var(--gray-200);
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      overflow: hidden;
    }

    .feature-card {
      background: var(--white);
      padding: 28px 24px;
      transition: background 0.15s;
    }

    .feature-card:hover { background: var(--gray-100); }

    .feature-icon {
      width: 32px; height: 32px;
      background: var(--gray-100);
      border: 1px solid var(--gray-200);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 16px;
    }

    .feature-icon svg { width: 16px; height: 16px; color: var(--gray-600); }

    .feature-title {
      font-size: 14px;
      font-weight: 500;
      color: var(--black);
      margin-bottom: 8px;
      letter-spacing: -0.01em;
    }

    .feature-desc {
      font-size: 13px;
      color: var(--gray-600);
      line-height: 1.6;
      font-weight: 300;
    }

    /* ---- FOOTER ---- */
    footer {
      border-top: 1px solid var(--gray-200);
      padding: 24px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    .footer-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .footer-brand {
      font-size: 12px;
      font-weight: 500;
      color: var(--black);
      font-family: var(--font-mono);
      letter-spacing: -0.01em;
    }

    .footer-sep {
      width: 1px;
      height: 14px;
      background: var(--gray-200);
    }

    .footer-links {
      display: flex;
      gap: 16px;
      list-style: none;
    }

    .footer-links a {
      font-size: 12px;
      color: var(--gray-400);
      text-decoration: none;
      transition: color 0.15s;
    }

    .footer-links a:hover { color: var(--black); }

    .footer-right {
      font-size: 12px;
      color: var(--gray-400);
      font-weight: 300;
    }

    .powered {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .powered svg { width: 12px; height: 12px; }

    /* ---- RESPONSIVE ---- */
    @media (max-width: 640px) {
      nav { padding: 0 16px; }
      .nav-links { display: none; }
      main { padding-top: 120px; }
      h1 { font-size: 36px; }
      .features-grid { grid-template-columns: 1fr; }
      footer { flex-direction: column; align-items: flex-start; }
    }

    /* ---- ANIM ---- */
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(12px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    .badge      { animation: fadeUp 0.4s ease both; }
    h1          { animation: fadeUp 0.4s 0.08s ease both; }
    .hero-sub   { animation: fadeUp 0.4s 0.14s ease both; }
    .search-wrap{ animation: fadeUp 0.4s 0.20s ease both; }
    .search-hint{ animation: fadeUp 0.4s 0.24s ease both; }
    .quick-links{ animation: fadeUp 0.4s 0.30s ease both; }
  </style>
</head>
<body>

  <!-- NAV -->
  <nav>
    <a class="nav-brand" href="/">
      <div class="nav-logo">
        <svg viewBox="0 0 14 14" xmlns="http://www.w3.org/2000/svg">
          <circle cx="7" cy="7" r="2.5"/>
          <path d="M7 1.5A5.5 5.5 0 0 1 12.5 7 5.5 5.5 0 0 1 7 12.5 5.5 5.5 0 0 1 1.5 7 5.5 5.5 0 0 1 7 1.5Z" stroke="white" stroke-width="1.2" fill="none"/>
        </svg>
      </div>
      <span class="nav-name">ObscuraProxy</span>
    </a>

    <ul class="nav-links">
      <li><a href="https://obscuraworks.com" target="_blank" rel="noopener">obscuraworks.com</a></li>
      <li><a href="https://github.com/NyxObscura/webproxy" target="_blank" rel="noopener">GitHub</a></li>
      <li><a href="https://obscuraworks.org" target="_blank" rel="noopener">obscuraworks.org</a></li>
    </ul>

    <div class="nav-cta">
      <a class="btn-ghost" href="https://github.com/NyxObscura/webproxy" target="_blank" rel="noopener">Docs</a>
      <a class="btn-primary" href="https://obscuraworks.com" target="_blank" rel="noopener">ObscuraWorks</a>
    </div>
  </nav>

  <!-- HERO -->
  <main>
    <span class="badge">
      <span class="badge-dot"></span>
      Powered by Cloudflare &mdash; webproxy.obscuraworks.org
    </span>

    <h1>Private web access,<br><strong>zero friction.</strong></h1>

    <p class="hero-sub">
      Route your traffic through ObscuraWorks' proxy infrastructure. No setup, no accounts — just paste a URL and go.
    </p>

    <div class="search-wrap">
      <div class="search-box">
        <span class="search-icon">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0Z"/>
          </svg>
        </span>
        <input type="text" id="urlInput" placeholder="URL or search term" autocomplete="off" spellcheck="false">
        <button id="goBtn">
          Go
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3"/>
          </svg>
        </button>
      </div>
    </div>

    <p class="search-hint">Press <kbd style="font-family:var(--font-mono);font-size:11px;background:var(--gray-100);border:1px solid var(--gray-200);padding:1px 5px;border-radius:3px;">Enter</kbd> to navigate</p>

    <div class="quick-links">
      <a class="quick-link" href="https://webproxy.obscuraworks.org/${sep}https://news.ycombinator.com" rel="noopener">news.ycombinator.com</a>
      <a class="quick-link" href="https://webproxy.obscuraworks.org/${sep}https://www.tsukuba.ac.jp/" rel="noopener">tsukuba.ac.jp</a>
      <a class="quick-link" href="https://webproxy.obscuraworks.org/${sep}https://www.example.com" rel="noopener">example.com</a>
      <a class="quick-link" href="https://github.com/NyxObscura/webproxy" target="_blank" rel="noopener">GitHub ↗</a>
    </div>

    <!-- FEATURES -->
    <div class="features-section">
      <p class="features-label">Why ObscuraProxy</p>
      <div class="features-grid">
        <div class="feature-card">
          <div class="feature-icon">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9-4.03-9-9-9Z"/>
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.6 9h16.8M3.6 15h16.8M12 3c-2.5 3-4 6-4 9s1.5 6 4 9M12 3c2.5 3 4 6 4 9s-1.5 6-4 9"/>
            </svg>
          </div>
          <div class="feature-title">Privacy by default</div>
          <div class="feature-desc">Your origin IP is masked. Destinations see ObscuraWorks' Cloudflare edge, not you.</div>
        </div>
        <div class="feature-card">
          <div class="feature-icon">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5 10.5 6l6.75 6.75L13.5 9.75V21M20.25 3h-3"/>
            </svg>
          </div>
          <div class="feature-title">Cloudflare edge</div>
          <div class="feature-desc">Traffic is handled at Cloudflare's global edge network — low latency, high availability.</div>
        </div>
        <div class="feature-card">
          <div class="feature-icon">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
              <path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5"/>
            </svg>
          </div>
          <div class="feature-title">Zero setup</div>
          <div class="feature-desc">No extension, no account, no config. Open the page, type a URL, done.</div>
        </div>
      </div>
    </div>
  </main>

  <!-- FOOTER -->
  <footer>
    <div class="footer-left">
      <span class="footer-brand">ObscuraWorks</span>
      <div class="footer-sep"></div>
      <ul class="footer-links">
        <li><a href="https://obscuraworks.com" target="_blank" rel="noopener">obscuraworks.com</a></li>
        <li><a href="https://obscuraworks.org" target="_blank" rel="noopener">obscuraworks.org</a></li>
        <li><a href="https://github.com/NyxObscura/webproxy" target="_blank" rel="noopener">GitHub</a></li>
      </ul>
    </div>
    <div class="footer-right">
      <span class="powered">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12" fill="currentColor">
          <circle cx="6" cy="6" r="5" fill="none" stroke="currentColor" stroke-width="1.2"/>
          <circle cx="6" cy="6" r="2"/>
        </svg>
        Runs on Cloudflare Workers
      </span>
    </div>
  </footer>

  <script>
    (function () {
      'use strict';

      var SEP = '${escapeForJS(sep)}';
      var input = document.getElementById('urlInput');
      var btn   = document.getElementById('goBtn');

      function buildTarget(val) {
        val = val.trim().replace(/\\s+/g, '');
        if (!val) return null;
        if (/^https?:\\/\\//i.test(val)) return val;
        if (val.includes('.') && !/\\s/.test(val)) return 'https://' + val;
        return 'https://duckduckgo.com/?q=' + encodeURIComponent(val);
      }

      function navigate() {
        var target = buildTarget(input.value);
        if (!target) return;
        window.location.href = '/' + SEP + target;
      }

      btn.addEventListener('click', navigate);
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') navigate();
      });
      input.addEventListener('paste', function () {
        setTimeout(function () {
          input.value = input.value.trim().replace(/\\s+/g, '');
        }, 0);
      });

      input.focus();
    })();
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-store',
    },
  });
}

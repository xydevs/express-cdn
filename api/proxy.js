const crypto = require('crypto')
const https = require('https')
const http = require('http')

// ── AES ──────────────────────────────────────────────────────────────────────

const SECRET_KEY = "xydevsworld"
let _aesKey = null

function getAesKeyBuffer() {
  if (!_aesKey) _aesKey = crypto.createHash('sha256').update(SECRET_KEY).digest()
  return _aesKey
}

function encryptToken(url) {
  const iv = crypto.randomBytes(16)
  const key = getAesKeyBuffer()
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encrypted = Buffer.concat([cipher.update(url, 'utf8'), cipher.final()])
  return Buffer.concat([iv, encrypted])
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function decryptToken(token) {
  let base64 = token.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4) base64 += '='
  const raw = Buffer.from(base64, 'base64')
  const iv = raw.slice(0, 16)
  const ciphertext = raw.slice(16)
  const key = getAesKeyBuffer()
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
}

// ── Content-type helpers ──────────────────────────────────────────────────────

function isM3U8(url, contentType) {
  const u = (url || '').toLowerCase()
  if (u.endsWith('.m3u8') || u.includes('.m3u8?')) return true
  return (contentType || '').toLowerCase().includes('mpegurl')
}

function isTSSegment(url, contentType) {
  const u = (url || '').toLowerCase()
  if (u.endsWith('.ts') || u.includes('.ts?')) return true
  return (contentType || '').toLowerCase().includes('video/mp2t')
}

function isVideoOrAudio(contentType) {
  const ct = (contentType || '').toLowerCase()
  return ct.startsWith('video/') || ct.startsWith('audio/')
}

// ── Native fetch dengan SSL fallback & Range support ─────────────────────────

const INSECURE_AGENT = new https.Agent({ rejectUnauthorized: false })
const SECURE_AGENT   = new https.Agent({ rejectUnauthorized: true })

function nativeFetch(urlString, headers) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(urlString)
    const isHttps = parsedUrl.protocol === 'https:'
    const lib = isHttps ? https : http

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: headers,
      agent: isHttps ? SECURE_AGENT : undefined,
      timeout: 30000,
    }

    const req = lib.request(options, resolve)
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')) })
    req.end()
  })
}

async function fetchWithSSLFallback(urlString, headers) {
  try {
    const res = await nativeFetch(urlString, headers)

    // 526 = Cloudflare SSL error dari upstream
    if (res.statusCode === 526 && urlString.startsWith('https://')) {
      res.destroy()
      return fetchHTTPFallback(urlString, headers)
    }

    // 3xx redirect — ikuti manual
    if (res.statusCode >= 301 && res.statusCode <= 308 && res.headers.location) {
      res.destroy()
      const redirectUrl = res.headers.location.startsWith('http')
        ? res.headers.location
        : new URL(res.headers.location, urlString).href
      return fetchWithSSLFallback(redirectUrl, headers)
    }

    return res
  } catch (err) {
    const errStr = err.message.toLowerCase()
    const isSSLErr = errStr.includes('certificate') || errStr.includes('ssl') ||
                     errStr.includes('tls') || errStr.includes('x509') ||
                     err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
                     err.code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
                     err.code === 'ERR_TLS_CERT_ALTNAME_INVALID'

    if (isSSLErr && urlString.startsWith('https://')) {
      // Coba InsecureSkipVerify dulu
      try {
        const parsedUrl = new URL(urlString)
        const options = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || 443,
          path: parsedUrl.pathname + parsedUrl.search,
          method: 'GET',
          headers,
          agent: INSECURE_AGENT,
          timeout: 30000,
        }
        return await new Promise((resolve, reject) => {
          const req = https.request(options, resolve)
          req.on('error', reject)
          req.on('timeout', () => { req.destroy(); reject(new Error('timeout')) })
          req.end()
        })
      } catch {
        // Last resort: downgrade HTTP
        return fetchHTTPFallback(urlString, headers)
      }
    }
    throw err
  }
}

function fetchHTTPFallback(httpsUrl, headers) {
  const httpUrl = httpsUrl.replace(/^https:\/\//i, 'http://')
  const parsedUrl = new URL(httpUrl)
  return new Promise((resolve, reject) => {
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 80,
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: { ...headers, 'Host': new URL(httpsUrl).hostname },
      timeout: 30000,
    }
    const req = http.request(options, resolve)
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')) })
    req.end()
  })
}

// ── CORS ──────────────────────────────────────────────────────────────────────

function setCORSHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Range, If-Range, If-Modified-Since, If-None-Match, Content-Type, Origin, Accept')
  res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges, Date, Server')
}

// ── Build upstream headers ────────────────────────────────────────────────────

function buildFetchHeaders(req, isLikelyM3U8, isLikelyTS, isDownloadManager) {
  const headers = {
    'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': req.headers['accept'] || '*/*',
    'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'Accept-Encoding': 'identity', // SELALU identity — hindari gzip/br yang bikin streaming rusak
    'Connection': 'keep-alive',
  }

  // ── Teruskan Range header — INI KUNCI anti-buffering ─────────────────────
  const rangeHeader = req.headers['range']
  if (rangeHeader) headers['Range'] = rangeHeader

  // Header conditional request
  ;['if-range', 'if-modified-since', 'if-none-match'].forEach(h => {
    if (req.headers[h]) headers[h.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join('-')] = req.headers[h]
  })

  if (isLikelyM3U8) headers['Cache-Control'] = 'no-cache'

  return headers
}

// ── M3U8 rewrite ─────────────────────────────────────────────────────────────

async function processM3U8(content, baseUrl, workerHost, endpoint) {
  const base = new URL(baseUrl)
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim()
    if (trimmed.startsWith('#') || trimmed === '') continue

    try {
      const absoluteUrl = trimmed.startsWith('http://') || trimmed.startsWith('https://')
        ? trimmed
        : new URL(trimmed, base).href

      const token = encryptToken(absoluteUrl)
      lines[i] = `${workerHost}${endpoint}${token}`
    } catch { /* biarkan line asli */ }
  }

  return lines.join('\n')
}

// ── File extension ────────────────────────────────────────────────────────────

function getFileExtension(contentType, pathname) {
  const ext = (pathname.split('.').pop() || '')
  if (ext && ext.length <= 5 && !ext.includes('/')) return `.${ext.toLowerCase()}`
  const map = {
    'video/mp4': '.mp4', 'video/webm': '.webm', 'audio/mpeg': '.mp3',
    'audio/ogg': '.ogg', 'image/jpeg': '.jpg', 'image/png': '.png',
    'image/gif': '.gif', 'image/webp': '.webp', 'application/pdf': '.pdf',
    'application/zip': '.zip', 'text/plain': '.txt', 'text/html': '.html',
  }
  return map[contentType.split(';')[0].trim().toLowerCase()] || '.bin'
}

// ── Pipe upstream → response dengan proper Range handling ────────────────────

function pipeResponse(upstream, res, statusCode) {
  res.status(statusCode)

  upstream.on('error', (err) => {
    console.error('Upstream pipe error:', err.message)
    if (!res.headersSent) res.status(502).end()
    else res.end()
  })

  upstream.pipe(res)
}

// ── Main proxy handler ────────────────────────────────────────────────────────

async function handleProxy(req, res, token, endpoint) {
  let decodedUrl
  try {
    decodedUrl = decryptToken(token)
  } catch (err) {
    return res.status(400).send('Invalid token: ' + err.message)
  }

  const isLikelyM3U8 = isM3U8(decodedUrl, '')
  const isLikelyTS   = isTSSegment(decodedUrl, '')
  const hasRange     = !!req.headers['range']
  const ua           = req.headers['user-agent'] || ''
  const isDownloadManager = /IDM|Download Manager|wget|curl/i.test(ua)

  const fetchHeaders = buildFetchHeaders(req, isLikelyM3U8, isLikelyTS, isDownloadManager)

  let upstream
  try {
    upstream = await fetchWithSSLFallback(decodedUrl, fetchHeaders)
  } catch (err) {
    return res.status(502).send('Fetch error: ' + err.message)
  }

  const upStatus      = upstream.statusCode
  const upHeaders     = upstream.headers
  const contentType   = upHeaders['content-type'] || ''
  const isM3U8Content = isM3U8(decodedUrl, contentType)
  const isTSContent   = isTSSegment(decodedUrl, contentType)
  const isMedia       = isVideoOrAudio(contentType)

  setCORSHeaders(res)

  // ── M3U8: rewrite segment URLs ──────────────────────────────────────────
  if (isM3U8Content) {
    const chunks = []
    for await (const chunk of upstream) chunks.push(chunk)
    const m3u8Text = Buffer.concat(chunks).toString('utf8')

    const reqUrl     = new URL(req.url, `https://${req.headers.host}`)
    const workerHost = `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}`
    const processed  = await processM3U8(m3u8Text, decodedUrl, workerHost, endpoint)
    const bodyBuf    = Buffer.from(processed, 'utf8')

    res.setHeader('Content-Type', 'application/vnd.apple.mpegurl; charset=utf-8')
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
    res.setHeader('Pragma', 'no-cache')
    res.setHeader('Expires', '0')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Content-Length', bodyBuf.length)
    res.status(200).end(bodyBuf)
    return
  }

  // ── TS segment: aggressive cache, stream langsung ───────────────────────
  if (isTSContent) {
    res.setHeader('Content-Type', upHeaders['content-type'] || 'video/mp2t')
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
    res.setHeader('Accept-Ranges', 'bytes')
    ;['content-length', 'content-range', 'etag', 'last-modified'].forEach(h => {
      if (upHeaders[h]) res.setHeader(h, upHeaders[h])
    })
    return pipeResponse(upstream, res, upStatus)
  }

  // ── Video/Audio MP4 dll: KUNCI anti-buffering ────────────────────────────
  if (isMedia || hasRange) {
    // Wajib: Accept-Ranges agar browser tahu bisa request chunk
    res.setHeader('Accept-Ranges', 'bytes')

    // Pass-through headers penting
    ;['content-type', 'content-length', 'content-range', 'etag', 'last-modified'].forEach(h => {
      if (upHeaders[h]) res.setHeader(h, upHeaders[h])
    })

    // Video: boleh cache di browser tapi revalidate — ini penting untuk preload
    if (hasRange) {
      // Partial content — cache agresif per chunk
      res.setHeader('Cache-Control', 'public, max-age=3600')
    } else {
      res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate')
    }

    res.removeHeader('Transfer-Encoding')
    res.removeHeader('Content-Encoding')

    // Status 206 untuk partial content, 200 untuk full
    return pipeResponse(upstream, res, upStatus)
  }

  // ── Download manager ─────────────────────────────────────────────────────
  if (isDownloadManager) {
    ;['content-type', 'content-length', 'content-range', 'etag', 'last-modified', 'accept-ranges'].forEach(h => {
      if (upHeaders[h]) res.setHeader(h, upHeaders[h])
    })
    res.setHeader('Accept-Ranges', 'bytes')
    res.setHeader('Cache-Control', 'public, max-age=3600')
    res.setHeader('X-CDN-Cache', 'HIT')
    return pipeResponse(upstream, res, upStatus)
  }

  // ── Fallback: content lainnya ────────────────────────────────────────────
  ;['content-type', 'content-length', 'content-range', 'etag', 'last-modified', 'accept-ranges'].forEach(h => {
    if (upHeaders[h]) res.setHeader(h, upHeaders[h])
  })
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.removeHeader('Transfer-Encoding')
  res.removeHeader('Content-Encoding')

  return pipeResponse(upstream, res, upStatus)
}

// ── Download mode ─────────────────────────────────────────────────────────────

async function handleDownload(req, res, token) {
  let decodedUrl
  try {
    decodedUrl = decryptToken(token)
  } catch (err) {
    return res.status(400).send('Invalid token: ' + err.message)
  }

  const fetchHeaders = {
    'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
    'Accept': '*/*',
    'Accept-Encoding': 'identity',
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache',
  }
  ;['range', 'if-range', 'if-modified-since', 'if-none-match'].forEach(h => {
    if (req.headers[h]) fetchHeaders[h] = req.headers[h]
  })

  let upstream
  try {
    upstream = await fetchWithSSLFallback(decodedUrl, fetchHeaders)
  } catch (err) {
    return res.status(502).send('Fetch error: ' + err.message)
  }

  const upHeaders   = upstream.headers
  const contentType = upHeaders['content-type'] || 'application/octet-stream'
  const fileExt     = getFileExtension(contentType, new URL(decodedUrl).pathname)

  setCORSHeaders(res)
  ;['content-type', 'content-length', 'content-range', 'etag', 'last-modified', 'accept-ranges'].forEach(h => {
    if (upHeaders[h]) res.setHeader(h, upHeaders[h])
  })
  res.setHeader('Accept-Ranges', 'bytes')
  res.setHeader('Content-Disposition', `attachment; filename="xydevs_cdn${fileExt}"`)
  res.setHeader('X-CDN-Wrapper', 'xydevs-cdn')
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.removeHeader('Content-Encoding')
  res.removeHeader('Transfer-Encoding')

  return pipeResponse(upstream, res, upstream.statusCode)
}

// ── Router / Entry point ──────────────────────────────────────────────────────

module.exports = async function handler(req, res) {
  const urlObj   = new URL(req.url, `https://${req.headers.host}`)
  const pathname = urlObj.pathname

  if (req.method === 'OPTIONS') {
    setCORSHeaders(res)
    res.setHeader('Access-Control-Max-Age', '86400')
    return res.status(200).end()
  }

  // HEAD request — sama seperti GET tapi tanpa body
  const isHead = req.method === 'HEAD'

  if (pathname.startsWith('/r/')) {
    const token = pathname.substring(3)
    if (!token) return res.status(400).send('Missing token')
    try {
      const decoded = decryptToken(token)
      res.setHeader('Location', decoded)
      return res.status(302).end()
    } catch (err) {
      return res.status(400).send('Invalid token: ' + err.message)
    }
  }

  if (pathname.startsWith('/w/')) {
    const token = pathname.substring(3)
    if (!token) return res.status(400).send('Missing token')
    return handleDownload(req, res, token)
  }

  if (pathname.startsWith('/vyreels/')) {
    const token = pathname.substring(9)
    if (!token) return res.status(400).send('Missing token')
    return handleProxy(req, res, token, '/vyreels/')
  }

  if (pathname.length > 1) {
    const token = pathname.substring(1)
    return handleProxy(req, res, token, '/')
  }

  res.setHeader('Content-Type', 'text/plain')
  return res.status(200).send('Hello World')
}

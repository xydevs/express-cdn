const crypto = require('crypto')

const SECRET_KEY = "xydevsworld"
let AES_KEY_BUFFER = null

function getAesKeyBuffer() {
  if (!AES_KEY_BUFFER) {
    AES_KEY_BUFFER = crypto.createHash('sha256').update(SECRET_KEY).digest()
  }
  return AES_KEY_BUFFER
}

function encryptToken(url) {
  const iv = crypto.randomBytes(16)
  const key = getAesKeyBuffer()
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encrypted = Buffer.concat([cipher.update(url, 'utf8'), cipher.final()])
  const combined = Buffer.concat([iv, encrypted])
  return combined.toString('base64')
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

function isM3U8(url, contentType) {
  const u = url.toLowerCase()
  if (u.endsWith('.m3u8') || u.includes('.m3u8?')) return true
  if (contentType) {
    const ct = contentType.toLowerCase()
    if (ct.includes('mpegurl')) return true
  }
  return false
}

function isTSSegment(url, contentType) {
  const u = url.toLowerCase()
  if (u.endsWith('.ts') || u.includes('.ts?')) return true
  if (contentType) {
    const ct = contentType.toLowerCase()
    if (ct.includes('video/mp2t')) return true
  }
  return false
}

async function processM3U8Content(content, baseUrl, workerHost, endpoint) {
  const lines = content.split('\n')
  const result = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith('#') || trimmed === '') {
      result.push(line)
      continue
    }
    try {
      let absoluteUrl
      if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        absoluteUrl = trimmed
      } else {
        absoluteUrl = new URL(trimmed, baseUrl).href
      }
      const token = encryptToken(absoluteUrl)
      result.push(`${workerHost}${endpoint}${token}`)
    } catch {
      result.push(line)
    }
  }
  return result.join('\n')
}

async function fetchWithSSLFallback(urlString, fetchHeaders) {
  const { default: fetch } = await import('node-fetch')

  try {
    const res = await fetch(urlString, { headers: fetchHeaders, redirect: 'follow' })
    if (res.status === 526 && urlString.startsWith('https://')) {
      const httpUrl = urlString.replace(/^https:\/\//i, 'http://')
      return await fetch(httpUrl, {
        headers: { ...fetchHeaders, 'Host': new URL(urlString).hostname },
        redirect: 'follow'
      })
    }
    return res
  } catch (err) {
    // Jika SSL error pada level Node.js (CERT_*), fallback ke HTTP
    if (
      err.code && (
        err.code.includes('CERT') ||
        err.code.includes('SSL') ||
        err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
        err.code === 'SELF_SIGNED_CERT_IN_CHAIN'
      ) && urlString.startsWith('https://')
    ) {
      const { default: fetchHttp } = await import('node-fetch')
      const https = require('https')
      const agent = new (require('https').Agent)({ rejectUnauthorized: false })
      return await fetchHttp(urlString, { headers: fetchHeaders, redirect: 'follow', agent })
    }
    throw err
  }
}

function setCORSHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Range, If-Range, If-Modified-Since, If-None-Match, Content-Type, Origin, Accept')
  res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges, Date, Server')
  res.setHeader('Access-Control-Max-Age', '86400')
}

function getFileExtension(contentType, pathname) {
  const ext = pathname.split('.').pop()
  if (ext && ext.length <= 5 && !ext.includes('/')) return `.${ext.toLowerCase()}`
  const map = {
    'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif',
    'image/webp': '.webp', 'video/mp4': '.mp4', 'video/webm': '.webm',
    'audio/mpeg': '.mp3', 'audio/ogg': '.ogg', 'application/pdf': '.pdf',
    'application/zip': '.zip', 'text/plain': '.txt', 'text/html': '.html'
  }
  return map[contentType.split(';')[0].trim().toLowerCase()] || '.bin'
}

module.exports = async function handler(req, res) {
  const url = new URL(req.url, `https://${req.headers.host}`)
  const pathname = url.pathname

  // OPTIONS preflight
  if (req.method === 'OPTIONS') {
    setCORSHeaders(res)
    return res.status(200).end()
  }

  // /r/ redirect
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

  // /w/ download mode
  if (pathname.startsWith('/w/')) {
    const token = pathname.substring(3)
    if (!token) return res.status(400).send('Missing token')
    return handleDownloadMode(token, req, res)
  }

  // /vyreels/ endpoint
  if (pathname.startsWith('/vyreels/')) {
    const token = pathname.substring(9)
    if (!token) return res.status(400).send('Missing token')
    return handleProxyRequest(token, req, res, url, '/vyreels/')
  }

  // root endpoint
  if (pathname.length > 1) {
    const token = pathname.substring(1)
    return handleProxyRequest(token, req, res, url, '/')
  }

  res.setHeader('Content-Type', 'text/plain')
  return res.status(200).send('Hello World')
}

async function handleProxyRequest(token, req, res, url, endpoint) {
  try {
    const decodedUrl = decryptToken(token)
    const targetUrl = new URL(decodedUrl)

    const userAgent = req.headers['user-agent'] || ''
    const isDownloadManager =
      userAgent.includes('IDM') || userAgent.includes('Download') ||
      userAgent.includes('wget') || userAgent.includes('curl') ||
      !!req.headers['range']

    const forwardHeaders = {}
    ;['range', 'if-range', 'if-modified-since', 'if-none-match'].forEach(h => {
      if (req.headers[h]) forwardHeaders[h] = req.headers[h]
    })

    const isLikelyM3U8 = isM3U8(decodedUrl, null)
    const isLikelyTS = isTSSegment(decodedUrl, null)

    const fetchHeaders = {
      'User-Agent': userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Accept': req.headers['accept'] || '*/*',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      'Connection': 'keep-alive',
      ...forwardHeaders
    }

    if (isLikelyM3U8 || isLikelyTS || !isDownloadManager) {
      fetchHeaders['Accept-Encoding'] = 'identity'
    }
    if (isLikelyM3U8) fetchHeaders['Cache-Control'] = 'no-cache'

    const upstream = await fetchWithSSLFallback(targetUrl.href, fetchHeaders)

    if (!upstream.ok) {
      return res.status(upstream.status).send(`Error fetching content: ${upstream.status} ${upstream.statusText}`)
    }

    const contentType = upstream.headers.get('content-type') || ''
    const isM3U8Content = isM3U8(decodedUrl, contentType)
    const isTSContent = isTSSegment(decodedUrl, contentType)

    setCORSHeaders(res)

    if (isM3U8Content) {
      const m3u8Text = await upstream.text()
      const workerHost = `${url.protocol}//${url.host}`
      const processed = await processM3U8Content(m3u8Text, decodedUrl, workerHost, endpoint)

      res.setHeader('Content-Type', 'application/vnd.apple.mpegurl; charset=utf-8')
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
      res.setHeader('Pragma', 'no-cache')
      res.setHeader('Expires', '0')
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('Content-Length', Buffer.byteLength(processed, 'utf8').toString())
      return res.status(200).send(processed)
    }

    // Pass-through headers
    ;['content-type', 'content-length', 'last-modified', 'etag', 'accept-ranges', 'content-range'].forEach(h => {
      const v = upstream.headers.get(h)
      if (v) res.setHeader(h, v)
    })

    if (isTSContent) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
      res.setHeader('X-Content-Type-Options', 'nosniff')
      if (!upstream.headers.get('content-type') || upstream.headers.get('content-type').includes('octet-stream')) {
        res.setHeader('Content-Type', 'video/mp2t')
      }
      return upstream.body.pipe(res)
    }

    if (isDownloadManager) {
      res.setHeader('Cache-Control', 'public, max-age=3600')
      res.setHeader('X-CDN-Cache', 'HIT')
    } else {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
      res.setHeader('Pragma', 'no-cache')
      res.setHeader('Expires', '0')
      res.setHeader('X-Accel-Buffering', 'no')
      res.removeHeader('Transfer-Encoding')
      res.removeHeader('Content-Encoding')
    }

    res.status(upstream.status)
    upstream.body.pipe(res)

  } catch (err) {
    res.status(400).send('Invalid token or bad URL: ' + err.message)
  }
}

async function handleDownloadMode(token, req, res) {
  try {
    const decodedUrl = decryptToken(token)
    const targetUrl = new URL(decodedUrl)
    const { default: fetch } = await import('node-fetch')

    const forwardHeaders = {}
    ;['range', 'if-range', 'if-modified-since', 'if-none-match'].forEach(h => {
      if (req.headers[h]) forwardHeaders[h] = req.headers[h]
    })

    const upstream = await fetch(targetUrl.href, {
      headers: {
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'Accept': req.headers['accept'] || '*/*',
        'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
        ...forwardHeaders
      }
    })

    if (!upstream.ok) {
      return res.status(upstream.status).send(`Error fetching content: ${upstream.status} ${upstream.statusText}`)
    }

    const contentType = upstream.headers.get('Content-Type') || 'application/octet-stream'
    const fileExt = getFileExtension(contentType, targetUrl.pathname)

    setCORSHeaders(res)
    ;['content-type', 'content-length', 'last-modified', 'etag', 'accept-ranges', 'content-range'].forEach(h => {
      const v = upstream.headers.get(h)
      if (v) res.setHeader(h, v)
    })

    res.setHeader('Content-Disposition', `attachment; filename="xydevs_cdn${fileExt}"`)
    res.setHeader('X-CDN-Wrapper', 'xydevs-cdn')
    res.setHeader('X-Original-URL', targetUrl.hostname)
    res.setHeader('X-Accel-Buffering', 'no')
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
    res.setHeader('Pragma', 'no-cache')
    res.setHeader('Expires', '0')
    res.removeHeader('Content-Encoding')
    res.removeHeader('Transfer-Encoding')

    res.status(upstream.status)
    upstream.body.pipe(res)

  } catch (err) {
    res.status(500).send('Download mode error: ' + err.message)
  }
}

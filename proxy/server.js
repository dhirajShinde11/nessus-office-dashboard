/**
 * Zero-dependency Node.js CORS & SSL Proxy for Tenable Nessus API
 * Handles self-signed certificates (rejectUnauthorized: false) and browser CORS headers
 * Automatically decompresses gzip/deflate/brotli payloads from Nessus
 * Provides REAL-TIME Live Network Connection & Physical Packet Tracking from the OS
 * 
 * Usage: node proxy/server.js
 * Default Port: 3000
 */

const http = require('http');
const https = require('https');
const url = require('url');
const zlib = require('zlib');
const { exec } = require('child_process');
const dns = require('dns');

const PORT = process.env.PORT || 3000;

// HTTPS Agent configured to allow self-signed certificates common on Nessus scanners
const insecureHttpsAgent = new https.Agent({
  rejectUnauthorized: false
});

// Cache of PID to Process Name (Refreshed every 4 seconds)
let processCache = new Map();
let lastProcessCacheTime = 0;

function refreshProcessCache() {
  const now = Date.now();
  if (now - lastProcessCacheTime < 4000 && processCache.size > 0) return;
  lastProcessCacheTime = now;

  exec('tasklist /fo csv /nh', (err, stdout) => {
    if (!err && stdout) {
      const newMap = new Map();
      const lines = stdout.split('\n');
      for (const line of lines) {
        const match = line.match(/^"([^"]+)","(\d+)"/);
        if (match) {
          newMap.set(match[2], match[1]);
        }
      }
      processCache = newMap;
    }
  });
}

// IP-to-Domain Cache
const ipDomainCache = new Map([
  ['127.0.0.1', 'localhost:8834'],
  ['8.8.8.8', 'dns.google'],
  ['8.8.4.4', 'dns.google'],
  ['1.1.1.1', 'one.one.one.one'],
  ['1.0.0.1', 'one.one.one.one']
]);

// Refresh DNS cache from Windows
function refreshDnsCache() {
  exec('powershell -NoProfile -Command "Get-DnsClientCache | Select-Object -Property Entry, Data | ConvertTo-Csv -NoTypeInformation"', (err, stdout) => {
    if (!err && stdout) {
      const lines = stdout.split('\n');
      for (const line of lines) {
        const match = line.match(/^"([^"]+)","([0-9a-fA-F:.]+)"/);
        if (match) {
          ipDomainCache.set(match[2].toLowerCase(), match[1].toLowerCase());
        }
      }
    }
  });
}

// Initial cache warm-up
refreshProcessCache();
refreshDnsCache();
setInterval(refreshDnsCache, 15000);

function guessDomainFromIp(remoteIp, remotePort) {
  if (ipDomainCache.has(remoteIp)) {
    return ipDomainCache.get(remoteIp);
  }

  // Common IP blocks for major providers
  if (remoteIp.startsWith('142.250.') || remoteIp.startsWith('172.217.') || remoteIp.startsWith('216.58.') || remoteIp.startsWith('34.54.')) {
    return 'google.com';
  }
  if (remoteIp.startsWith('104.16.') || remoteIp.startsWith('104.18.') || remoteIp.startsWith('172.64.') || remoteIp.startsWith('162.159.')) {
    return 'cloudflare.net';
  }
  if (remoteIp.startsWith('52.') || remoteIp.startsWith('20.') || remoteIp.startsWith('13.') || remoteIp.startsWith('40.')) {
    return 'microsoft.com';
  }
  if (remoteIp.startsWith('54.') || remoteIp.startsWith('3.') || remoteIp.startsWith('18.') || remoteIp.startsWith('35.')) {
    return 'amazonaws.com';
  }
  if (remoteIp.startsWith('140.82.') || remoteIp.startsWith('192.30.255.')) {
    return 'github.com';
  }

  // Reverse DNS lookup in background to populate cache
  try {
    dns.reverse(remoteIp, (err, hostnames) => {
      if (!err && hostnames && hostnames.length > 0) {
        ipDomainCache.set(remoteIp, hostnames[0].toLowerCase());
      }
    });
  } catch (e) {}

  return remotePort === 443 ? `https://${remoteIp}` : remoteIp;
}

const server = http.createServer((req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, X-ApiKeys, Authorization');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);

  // ENDPOINT 1: REAL LIVE PHYSICAL NETWORK TELEMETRY FROM WINDOWS
  if (parsedUrl.pathname === '/api/live-traffic') {
    refreshProcessCache();

    exec('netstat -ano -p tcp', { maxBuffer: 1024 * 1024 }, (err, stdout) => {
      if (err || !stdout) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          online: false,
          message: 'Error executing netstat or offline',
          connections: []
        }));
        return;
      }

      const lines = stdout.split('\n');
      const activeConnections = [];
      let detectedLocalIp = '10.101.133.29';

      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5 && parts[0] === 'TCP') {
          const [, local, remote, state, pid] = parts;
          if (state === 'ESTABLISHED') {
            const lastColonRemote = remote.lastIndexOf(':');
            const remoteIp = lastColonRemote > -1 ? remote.substring(0, lastColonRemote) : remote;
            const remotePort = lastColonRemote > -1 ? parseInt(remote.substring(lastColonRemote + 1), 10) : 0;

            const lastColonLocal = local.lastIndexOf(':');
            const localIp = lastColonLocal > -1 ? local.substring(0, lastColonLocal) : local;
            const localPort = lastColonLocal > -1 ? parseInt(local.substring(lastColonLocal + 1), 10) : 0;

            // Only capture external traffic (not localhost / loopback)
            if (remoteIp && !remoteIp.startsWith('127.') && remoteIp !== '[::1]' && remoteIp !== '0.0.0.0' && remoteIp !== '*') {
              if (localIp && !localIp.startsWith('127.') && localIp !== '0.0.0.0') {
                detectedLocalIp = localIp;
              }

              const procName = processCache.get(pid) || `Process (${pid})`;
              const domain = guessDomainFromIp(remoteIp, remotePort);

              activeConnections.push({
                localIp: localIp,
                localPort: localPort,
                remoteIp: remoteIp,
                remotePort: remotePort,
                pid: pid,
                processName: procName,
                domain: domain,
                state: state
              });
            }
          }
        }
      }

      const isOnline = activeConnections.length > 0;

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        online: isOnline,
        timestamp: new Date().toLocaleTimeString(),
        localIp: detectedLocalIp,
        activeSocketCount: activeConnections.length,
        connections: activeConnections,
        message: isOnline 
          ? `Physical Network Active (${activeConnections.length} live sockets)` 
          : 'Internet connection is disconnected or idle. 0 external network sockets.'
      }));
    });
    return;
  }

  // ENDPOINT 2: TENABLE NESSUS CORS & SSL PROXY
  if (parsedUrl.pathname === '/api/nessus') {
    const targetUrlString = parsedUrl.query.target;
    if (!targetUrlString) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing required ?target= query parameter' }));
      return;
    }

    let targetParsed;
    try {
      targetParsed = new URL(targetUrlString);
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid target URL: ' + e.message }));
      return;
    }

    const isHttps = targetParsed.protocol === 'https:';
    const client = isHttps ? https : http;

    // Filter headers to pass through
    const forwardHeaders = { ...req.headers };
    delete forwardHeaders.host;
    delete forwardHeaders.origin;
    delete forwardHeaders.referer;
    delete forwardHeaders['accept-encoding']; // Ask Nessus for raw uncompressed data

    const proxyOptions = {
      protocol: targetParsed.protocol,
      hostname: targetParsed.hostname,
      port: targetParsed.port || (isHttps ? 443 : 80),
      path: targetParsed.pathname + (targetParsed.search || ''),
      method: req.method,
      headers: forwardHeaders,
      agent: isHttps ? insecureHttpsAgent : undefined
    };

    const proxyReq = client.request(proxyOptions, (proxyRes) => {
      const encoding = (proxyRes.headers['content-encoding'] || '').toLowerCase();
      let stream = proxyRes;

      if (encoding === 'gzip') {
        stream = proxyRes.pipe(zlib.createGunzip());
      } else if (encoding === 'deflate') {
        stream = proxyRes.pipe(zlib.createInflate());
      } else if (encoding === 'br') {
        stream = proxyRes.pipe(zlib.createBrotliDecompress());
      }

      res.writeHead(proxyRes.statusCode, {
        'Content-Type': proxyRes.headers['content-type'] || 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*'
      });

      stream.pipe(res);

      stream.on('error', (streamErr) => {
        console.error('[Decompression Error]', streamErr.message);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Failed to decompress Nessus payload', details: streamErr.message }));
        }
      });
    });

    proxyReq.on('error', (err) => {
      console.error('[Proxy Error]', err.message);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Proxy unable to reach Nessus target',
          details: err.message
        }));
      }
    });

    // Pipe request body for POST/PUT
    req.pipe(proxyReq);
  } else if (parsedUrl.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'Nessus & Live Traffic SOC Proxy' }));
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found. Endpoints are /api/nessus and /api/live-traffic');
  }
});

server.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`  Nessus & Live Network Proxy active on http://localhost:${PORT}`);
  console.log(`  Real physical network telemetry endpoint: /api/live-traffic`);
  console.log(`  Tenable Nessus CORS & SSL bypass endpoint: /api/nessus`);
  console.log(`=======================================================`);
});

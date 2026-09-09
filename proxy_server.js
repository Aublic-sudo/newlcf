// proxy_server.js
// Standalone zero-dependency HTTP server + Reverse Proxy for Video Player, Secure Player v3 & HLS streams
// Compatible with both Local Node.js and Vercel Serverless Functions

const http = require('http');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');

const PORT = process.env.PORT || 3000;
const BASE_DIR = __dirname;
let currentTargetOrigin = 'https://player.appx.co.in';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.m3u8': 'application/vnd.apple.mpegurl',
  '.ts': 'video/mp2t',
  '.mp4': 'video/mp4'
};

const DUMMY_PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');

function rewriteM3U8(content, baseUrlStr) {
  try {
    const baseUrl = new URL(baseUrlStr);
    const lines = content.split('\n');
    const rewritten = lines.map(line => {
      const trimmed = line.trim();
      if (!trimmed) return line;

      // Handle URI attributes in tags like #EXT-X-KEY:METHOD=AES-128,URI="..."
      if (trimmed.startsWith('#') && trimmed.includes('URI="')) {
        return trimmed.replace(/URI=["']([^"']+)["']/g, (m, uri) => {
          if (!uri.includes('/') && !uri.includes('.') && !uri.startsWith('http')) {
            return m;
          }
          let absUri = uri;
          try {
            absUri = new URL(uri, baseUrl).href;
          } catch(e) {}
          return `URI="/proxy?url=${encodeURIComponent(absUri)}"`;
        });
      }

      if (trimmed.startsWith('#')) return line;

      try {
        const abs = new URL(trimmed, baseUrl).href;
        return `/proxy?url=${encodeURIComponent(abs)}`;
      } catch(e) {
        return line;
      }
    });

    return rewritten.join('\n');
  } catch (err) {
    return content;
  }
}

function sendResponse(res, status, headers, body) {
  if (typeof res.writeHead === 'function') {
    res.writeHead(status, headers);
  } else {
    if (typeof res.status === 'function') res.status(status);
    for (const [k, v] of Object.entries(headers)) {
      if (typeof res.setHeader === 'function') res.setHeader(k, v);
    }
  }
  if (body !== undefined) {
    res.end(body);
  }
}

async function forwardUpstream(targetUrlStr, req, res) {
  try {
    if (targetUrlStr.includes('/images/undefined/')) {
      targetUrlStr = targetUrlStr.replace('/images/undefined/', '/images/watermark/');
    }

    if ((targetUrlStr.includes('/secure-player-v3') || targetUrlStr.includes('/secure-player?')) && targetUrlStr.includes('classx.co.in')) {
      targetUrlStr = targetUrlStr.replace(/https?:\/\/[^\/]+/, 'https://player.appx.co.in');
    }

    const targetUrl = new URL(targetUrlStr);
    if (targetUrl.origin && (targetUrl.origin.includes('classx') || targetUrl.origin.includes('appx') || targetUrl.origin.includes('akamai'))) {
      currentTargetOrigin = targetUrl.origin;
    }

    const isClassX = targetUrl.hostname.includes('classx.co.in') || targetUrl.hostname.includes('appx-play');
    const isAkamai = targetUrl.hostname.includes('akamai.net.in');
    const targetOrigin = (targetUrl.origin && targetUrl.origin !== 'null') ? targetUrl.origin : 'https://player.appx.co.in';

    const fetchHeaders = {
      'User-Agent': isClassX 
        ? 'Mozilla/5.0 (Linux; Android 12; SM-A528B Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.5481.154 Safari/537.36'
        : (req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'),
      'Accept': req.headers['accept'] || '*/*',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      'Referer': isClassX ? 'https://player.akamai.net.in/' : (targetOrigin + '/'),
      'Origin': isClassX ? 'https://player.akamai.net.in' : targetOrigin
    };

    if (isClassX) {
      fetchHeaders['X-Requested-With'] = 'co.shield.iugdu';
      fetchHeaders['Cookie'] = 'appxplayer=Rx4zsYq0+OHD1cbegiQ4Ya1PpBldcT0LYYtbyjBeYSpuCRh0yCBL00fSuoCcav2Agbz95fuOR6ppLzsXL6nSQo4WdJaLNqpazJ4186DTRqL4nw9bzaxy4jj7Ob6G68vbn6ut9rRdQGpsvGhVPex07A==:ZmVkY2JhOTg3NjU0MzIxMA==';
    }

    // Forward API headers for Akamai and Appx endpoints
    const forwardedHeaders = [
      'authorization', 'auth-key', 'client-service', 'user-id',
      'device-type', 'app-version', 'source', 'token', 'language', 'range'
    ];
    forwardedHeaders.forEach(h => {
      if (req.headers[h]) fetchHeaders[h] = req.headers[h];
    });

    // Default Akamai API auth headers so requests never fail with 401
    if (isAkamai) {
      if (!fetchHeaders['Client-Service'] && !fetchHeaders['client-service']) fetchHeaders['Client-Service'] = 'Appx';
      if (!fetchHeaders['Auth-Key'] && !fetchHeaders['auth-key']) fetchHeaders['Auth-Key'] = 'appxapi';
      if (!fetchHeaders['source']) fetchHeaders['source'] = 'android';
      if (!fetchHeaders['User-ID'] && !fetchHeaders['user-id']) fetchHeaders['User-ID'] = '0';
    }

    let requestBody = null;
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
      if (req.body) {
        if (Buffer.isBuffer(req.body)) {
          requestBody = req.body;
        } else if (typeof req.body === 'string') {
          requestBody = Buffer.from(req.body);
        } else if (typeof req.body === 'object') {
          requestBody = Buffer.from(JSON.stringify(req.body));
        }
      } else {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        if (chunks.length > 0) requestBody = Buffer.concat(chunks);
      }
      if (req.headers['content-type']) fetchHeaders['Content-Type'] = req.headers['content-type'];
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 25000);

    let upstreamRes;
    try {
      upstreamRes = await fetch(targetUrlStr, {
        method: req.method,
        headers: fetchHeaders,
        body: requestBody,
        redirect: 'follow',
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const contentType = upstreamRes.headers.get('content-type') || '';
    const responseHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE',
      'Access-Control-Allow-Headers': '*',
      'Content-Type': contentType
    };

    if (upstreamRes.headers.has('content-range')) responseHeaders['Content-Range'] = upstreamRes.headers.get('content-range');
    if (upstreamRes.headers.has('accept-ranges')) responseHeaders['Accept-Ranges'] = upstreamRes.headers.get('accept-ranges');

    // Case 1: HLS Playlists / M3U8 Manifests
    if (targetUrl.pathname.endsWith('.m3u8') || contentType.includes('mpegurl') || contentType.includes('application/x-mpegurl')) {
      let m3u8Text = await upstreamRes.text();
      let rewritten = rewriteM3U8(m3u8Text, targetUrlStr);
      responseHeaders['Content-Type'] = 'application/vnd.apple.mpegurl';
      sendResponse(res, upstreamRes.status, responseHeaders, rewritten);
      return;
    }

    // Case 2: HTML Page (e.g. Next.js Secure Player or Combined Img Player)
    if (contentType.includes('text/html')) {
      let html = await upstreamRes.text();

      if (html.trim().startsWith('#EXTM3U')) {
        let rewritten = rewriteM3U8(html, targetUrlStr);
        responseHeaders['Content-Type'] = 'application/vnd.apple.mpegurl';
        sendResponse(res, upstreamRes.status, responseHeaders, rewritten);
        return;
      }

      // Rewrite static <script src="...">, <link href="...">, <img src="..."> tags
      html = html.replace(/(<(?:script|link|img)\b[^>]*(?:src|href)=["'])([^"']+)(["'][^>]*>)/gi, (match, prefix, link, suffix) => {
        if (link.startsWith('http://') || link.startsWith('https://')) {
          if (link.includes('appx.co.in') || link.includes('classx.co.in')) {
            return prefix + '/proxy?url=' + encodeURIComponent(link) + suffix;
          }
          return match;
        }
        if (link.startsWith('data:') || link.startsWith('#')) return match;

        const full = link.startsWith('/') ? (targetUrl.origin + link) : (targetUrl.origin + '/' + link);
        return prefix + '/proxy?url=' + encodeURIComponent(full) + suffix;
      });

      // Clean report / alert button from raw HTML
      html = html.replace(/<button[^>]*>[\s\S]*?21\.73 18[\s\S]*?<\/button>/gi, '');

      // Inject runtime interceptor
      const targetUrlEscaped = targetUrlStr.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      const injection = `
<style id="custom-appx-player-enhancements">
  path[d*="21.73"],
  path[d*="m21.73 18"],
  svg:has(path[d*="21.73"]),
  button:has(path[d*="21.73"]),
  [aria-label*="report" i],
  [title*="report" i],
  .report-issue,
  .report-btn {
    display: none !important;
    visibility: hidden !important;
    opacity: 0 !important;
    pointer-events: none !important;
    width: 0 !important;
    height: 0 !important;
  }

  /* Embedded Close Button (Top-Right "✕") */
  #appx-inline-close-btn {
    position: fixed;
    top: 10px;
    right: 12px;
    z-index: 2147483647;
    background: rgba(15, 23, 42, 0.65);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 34px;
    height: 34px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
    transition: background-color 0.2s ease, transform 0.15s ease;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
  }
  #appx-inline-close-btn:hover {
    background: rgba(239, 68, 68, 0.85);
    border-color: rgba(239, 68, 68, 1);
    transform: scale(1.1);
  }
  #appx-inline-close-btn svg {
    width: 18px;
    height: 18px;
    stroke: currentColor;
    stroke-width: 2.5;
    fill: none;
    stroke-linecap: round;
    stroke-linejoin: round;
  }

  
</style>
<script>
(function() {
  var proxyPrefix = window.location.origin + '/proxy?url=';
  var targetOrigin = "${targetUrl.origin}";

  // Prevent Edge/Chrome Tracking Prevention errors with storage
  try {
    var _testLs = window.localStorage;
    _testLs.setItem('__p_test__', '1');
    _testLs.removeItem('__p_test__');
  } catch(err) {
    try {
      var _mem = {};
      var mock = {
        getItem: function(k) { return _mem.hasOwnProperty(k) ? _mem[k] : null; },
        setItem: function(k, v) { _mem[k] = String(v); },
        removeItem: function(k) { delete _mem[k]; },
        clear: function() { _mem = {}; },
        get length() { return Object.keys(_mem).length; },
        key: function(i) { return Object.keys(_mem)[i] || null; }
      };
      Object.defineProperty(window, 'localStorage', { value: mock, configurable: true, writable: true });
      Object.defineProperty(window, 'sessionStorage', { value: mock, configurable: true, writable: true });
    } catch(e) {}
  }

  // Next.js Route Synchronization
  try {
    var rawTargetUrl = "${targetUrlEscaped}";
    var parsedTarget = new URL(rawTargetUrl);
    if (window.history && window.history.replaceState) {
      var desiredPath = parsedTarget.pathname + parsedTarget.search + parsedTarget.hash;
      if (window.location.pathname !== parsedTarget.pathname || window.location.search !== parsedTarget.search) {
        window.history.replaceState(null, '', desiredPath);
      }
    }
  } catch(e) {}

  function fixUrl(u) {
    if (typeof u !== 'string' || !u || u.includes('/proxy?url=')) return u;
    if (u.startsWith('blob:') || u.startsWith('data:') || u.startsWith('javascript:') || u.startsWith('about:') || u.startsWith('ws:') || u.startsWith('wss:')) return u;
    var finalUrl = u;
    if (finalUrl.includes('/images/undefined/')) {
      finalUrl = finalUrl.replace('/images/undefined/', '/images/watermark/');
    }
    if (finalUrl.startsWith(window.location.origin)) {
      finalUrl = targetOrigin + finalUrl.substring(window.location.origin.length);
    } else if (finalUrl.startsWith('/')) {
      finalUrl = targetOrigin + finalUrl;
    } else if (!finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
      finalUrl = targetOrigin + '/' + finalUrl;
    }
    return proxyPrefix + encodeURIComponent(finalUrl);
  }

  // Bridge window.MS and window.keyString for secure-player manifest decryption
  var _rawMS = {};
  var _preservedKey = '';
  try {
    Object.defineProperty(window, 'keyString', {
      set: function(v) { if (v) _preservedKey = v; },
      get: function() { return _preservedKey; },
      configurable: true
    });

    Object.defineProperty(window, 'MS', {
      set: function(val) {
        if (val && typeof val === 'object') {
          for (var k in val) {
            _rawMS[k] = val[k];
            _rawMS[fixUrl(k)] = val[k];
            try {
              var dec = decodeURIComponent(k);
              _rawMS[dec] = val[k];
              _rawMS[fixUrl(dec)] = val[k];
            } catch(e) {}
          }
        }
      },
      get: function() {
        return new Proxy(_rawMS, {
          get: function(target, prop) {
            if (typeof prop === 'string') {
              if (target[prop]) return target[prop];
              for (var key in target) {
                if (prop.includes(encodeURIComponent(key)) || key.includes(prop) || prop.endsWith(key) || key.endsWith(prop)) {
                  return target[key];
                }
              }
            }
            return target[prop];
          }
        });
      },
      configurable: true
    });
  } catch(e) {}

  // Safeguard watermark loaders
  function patchWatermarkFunctions() {
    if (window.loadScriptFromImage && !window.loadScriptFromImage.__patched) {
      var origVJS = window.loadScriptFromImage;
      var patchedVJS = function(elementId, playerConfig, imagePath, videoSource, videoOptions) {
        if (!imagePath || typeof imagePath !== 'string' || imagePath.trim().length === 0 || imagePath.includes('undefined')) {
          imagePath = '/uhs-hls-player/images/watermark/video1-uhs4.png';
        }
        return origVJS.call(this, elementId, playerConfig, imagePath, videoSource, videoOptions);
      };
      patchedVJS.__patched = true;
      window.loadScriptFromImage = patchedVJS;
    }

    if (window.loadHLSPlayerFromImage && !window.loadHLSPlayerFromImage.__patched) {
      var origHLS = window.loadHLSPlayerFromImage;
      var patchedHLS = function(imagePath, videoUrl, videoElementId, hlsOptions) {
        if (!imagePath || typeof imagePath !== 'string' || imagePath.trim().length === 0 || imagePath.includes('undefined')) {
          imagePath = '/uhs-hls-player/images/watermark/hls-uhs4.png';
        }
        return origHLS.call(this, imagePath, videoUrl, videoElementId, hlsOptions);
      };
      patchedHLS.__patched = true;
      window.loadHLSPlayerFromImage = patchedHLS;
    }
  }

  ['loadScriptFromImage', 'loadHLSPlayerFromImage'].forEach(function(fnName) {
    var _fn = window[fnName];
    try {
      Object.defineProperty(window, fnName, {
        set: function(fn) {
          _fn = fn;
          patchWatermarkFunctions();
        },
        get: function() {
          return _fn;
        },
        configurable: true
      });
    } catch(e) {}
  });

  // Intercept Script Prototype src for Webpack chunk loading
  try {
    var origScriptDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (origScriptDesc && origScriptDesc.set) {
      Object.defineProperty(HTMLScriptElement.prototype, 'src', {
        set: function(val) {
          return origScriptDesc.set.call(this, fixUrl(val));
        },
        get: function() {
          return origScriptDesc.get.call(this);
        }
      });
    }
  } catch (e) {}

  // Intercept HTMLMediaElement Prototype src
  try {
    var origMediaDesc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src');
    if (origMediaDesc && origMediaDesc.set) {
      Object.defineProperty(HTMLMediaElement.prototype, 'src', {
        set: function(val) {
          return origMediaDesc.set.call(this, fixUrl(val));
        },
        get: function() {
          return origMediaDesc.get.call(this);
        }
      });
    }
  } catch (e) {}

  // Intercept HTMLSourceElement Prototype src
  try {
    var origSourceDesc = Object.getOwnPropertyDescriptor(HTMLSourceElement.prototype, 'src');
    if (origSourceDesc && origSourceDesc.set) {
      Object.defineProperty(HTMLSourceElement.prototype, 'src', {
        set: function(val) {
          return origSourceDesc.set.call(this, fixUrl(val));
        },
        get: function() {
          return origSourceDesc.get.call(this);
        }
      });
    }
  } catch (e) {}

  // Intercept Web Workers
  try {
    var origWorker = window.Worker;
    window.Worker = function(scriptUrl, options) {
      return new origWorker(fixUrl(scriptUrl), options);
    };
  } catch(e) {}

  var origXHR = window.XMLHttpRequest.prototype.open;
  window.XMLHttpRequest.prototype.open = function(m, u) {
    return origXHR.apply(this, [m, fixUrl(u)].concat(Array.prototype.slice.call(arguments, 2)));
  };

  var origFetch = window.fetch;
  window.fetch = function(r, i) {
    var target = r;
    if (typeof r === 'string') {
      target = fixUrl(r);
    } else if (r && r.url) {
      target = fixUrl(r.url);
    }
    return origFetch.call(window, target, i);
  };

  var origCreateElement = document.createElement;
  document.createElement = function(tagName, options) {
    var el = origCreateElement.call(document, tagName, options);
    if (tagName && (tagName.toLowerCase() === 'script' || tagName.toLowerCase() === 'source' || tagName.toLowerCase() === 'video')) {
      var origSetAttr = el.setAttribute;
      el.setAttribute = function(name, val) {
        if (name === 'src') val = fixUrl(val);
        return origSetAttr.call(el, name, val);
      };
    }
    return el;
  };

  function purgeReportBtn() {
    var paths = document.querySelectorAll('path');
    for (var i = 0; i < paths.length; i++) {
      var d = paths[i].getAttribute('d') || '';
      if (d.indexOf('21.73') !== -1 || d.indexOf('m21.73 18') !== -1) {
        var target = paths[i].closest('button') || paths[i].closest('a') || paths[i].closest('svg');
        if (target) target.remove();
      }
    }
  }

  function closePlayerAction(e) {
    if (e) {
      e.stopPropagation();
      e.preventDefault();
    }
    try {
      if (document.fullscreenElement || document.webkitFullscreenElement || document.mozFullScreenElement || document.msFullscreenElement) {
        if (document.exitFullscreen) document.exitFullscreen().catch(function(){});
        else if (document.webkitExitFullscreen) document.webkitExitFullscreen();
      }
      if (window.parent && window.parent !== window && window.parent.document && (window.parent.document.fullscreenElement || window.parent.document.webkitFullscreenElement)) {
        if (window.parent.document.exitFullscreen) window.parent.document.exitFullscreen().catch(function(){});
        else if (window.parent.document.webkitExitFullscreen) window.parent.document.webkitExitFullscreen();
      }
    } catch(err) {}

    try {
      var videos = document.querySelectorAll('video');
      for (var i = 0; i < videos.length; i++) {
        videos[i].pause();
      }
    } catch(err) {}

    try {
      if (window.parent && window.parent !== window) {
        if (typeof window.parent.closeProPlayer === 'function') {
          window.parent.closeProPlayer();
          return;
        }
        if (typeof window.parent.closePlayer === 'function') {
          window.parent.closePlayer();
          return;
        }
        window.parent.postMessage({ type: 'CLOSE_PLAYER' }, '*');
      }
    } catch(err) {}
  }

  function injectCloseBtn() {
    if (document.getElementById('appx-inline-close-btn')) return;
    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.id = 'appx-inline-close-btn';
    closeBtn.title = 'Close / Exit Player (Esc)';
    closeBtn.setAttribute('aria-label', 'Close player');
    closeBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
    closeBtn.onclick = closePlayerAction;
    if (document.body) document.body.appendChild(closeBtn);
  }

  

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      closePlayerAction(e);
    }
  });

  var _domTimer = null;
  function scheduleDomCheck() {
    if (_domTimer) return;
    _domTimer = setTimeout(function() {
      _domTimer = null;
      purgeReportBtn();
      injectCloseBtn();
      
      patchWatermarkFunctions();
    }, 100);
  }

  try {
    new MutationObserver(scheduleDomCheck).observe(document.documentElement, { childList: true, subtree: true });
  } catch(e) {}

  window.addEventListener('DOMContentLoaded', scheduleDomCheck);
  window.addEventListener('load', scheduleDomCheck);
})();
</script>
`;

      if (html.includes('<head>')) {
        html = html.replace('<head>', '<head>' + injection);
      } else {
        html = injection + html;
      }

      sendResponse(res, upstreamRes.status, responseHeaders, html);
      return;
    }

    // Case 3: JavaScript Files
    if (contentType.includes('javascript') || contentType.includes('ecmascript') || targetUrl.pathname.endsWith('.js')) {
      let js = await upstreamRes.text();

      // Specific patch for _0x64f3de (video-uhs3-o3.js)
      const targetExtFn1 = "function _0x64f3de(_0x5e1372){try{const _0x30e3c3=new URL(_0x5e1372)['pathname'],_0x1a0b4d=/\\.\\w+$/,_0xf0bca6=_0x30e3c3['match'](_0x1a0b4d);return _0xf0bca6?_0xf0bca6[0x0]['substring'](0x1):null;}catch(_0x3c28e2){return null;}}";
      const patchedExtFn1 = "function _0x64f3de(_0x5e1372){try{let _u=String(_0x5e1372);while(_u.includes('url=')||_u.includes('http%3A')||_u.includes('https%3A')){try{if(_u.includes('url=')){_u=decodeURIComponent(_u.split('url=')[1].split('&')[0]);}else{_u=decodeURIComponent(_u.replace(/^.*?https?%/i,function(m){return m.slice(-6);}));}}catch(e){break;}}_u=_u.split('#')[0].split('?')[0];const _0x30e3c3=new URL(_u.startsWith('http')?_u:('https://player.appx.co.in/'+_u))['pathname'],_0x1a0b4d=/\\.\\w+$/,_0xf0bca6=_0x30e3c3['match'](_0x1a0b4d);return _0xf0bca6?_0xf0bca6[0x0]['substring'](0x1):'';}catch(_0x3c28e2){return '';}}";
      if (js.includes(targetExtFn1)) {
        js = js.replace(targetExtFn1, patchedExtFn1);
      }

      // Generic patch for all extension extractors
      const genericExtRegex = /function\s+([_a-zA-Z0-9]+)\s*\(\s*([_a-zA-Z0-9]+)\s*\)\s*\{\s*try\s*\{\s*const\s+[_a-zA-Z0-9]+\s*=\s*new\s+URL\(\s*\2\s*\)\s*\[\s*['"]pathname['"]\s*\]\s*,\s*[_a-zA-Z0-9]+\s*=\s*\/\s*\\\.\s*\\w\+\s*\$\s*\/\s*,\s*[_a-zA-Z0-9]+\s*=\s*[_a-zA-Z0-9]+\[\s*['"]match['"]\s*\]\([_a-zA-Z0-9]+\)\s*;\s*return\s+[_a-zA-Z0-9]+\s*\?\s*[_a-zA-Z0-9]+\[\s*0x0\s*\]\[\s*['"]substring['"]\s*\]\(\s*0x1\s*\)\s*:\s*null\s*;\s*\}\s*catch\s*\(\s*[_a-zA-Z0-9]+\s*\)\s*\{\s*return\s+null\s*;\s*\}\s*\}/g;
      js = js.replace(genericExtRegex, (match, fnName, argName) => {
        return `function ${fnName}(${argName}){try{let _u=String(${argName});while(_u.includes('url=')||_u.includes('http%3A')||_u.includes('https%3A')){try{if(_u.includes('url=')){_u=decodeURIComponent(_u.split('url=')[1].split('&')[0]);}else{_u=decodeURIComponent(_u.replace(/^.*?https?%/i,function(m){return m.slice(-6);}));}}catch(e){break;}}_u=_u.split('#')[0].split('?')[0];const _parsed=new URL(_u.startsWith('http')?_u:('https://player.appx.co.in/'+_u))['pathname'],_m=_parsed.match(/\\.\\w+$/);return _m?_m[0].substring(1):'';}catch(_err){return '';}}`;
      });

      // Fix decryption function s(e,t,n,i) in 7474.js on quality switch
      const targetSFn = 'function s(e,t,n,i){let o=a.from(t,"base64"),s=a.from(n,"base64"),u=a.from(e,"base64"),d=r().createDecipheriv("aes-".concat(l[i].key,"-cbc"),o,s),c=d.update(u);return(c=a.concat([c,d.final()])).toString("utf-8")}';
      const patchedSFn = 'function s(e,t,n,i){try{if(!t)t=window.lv||window.keyString||"";if(!n)n=window.ivb6||"";if(!e)return e||"";let o=a.from(String(t),"base64"),s=a.from(String(n),"base64"),u=a.from(String(e),"base64"),k=(l[i]||l[8]||{key:"256"}).key,d=r().createDecipheriv("aes-".concat(k,"-cbc"),o,s),c=d.update(u);return(c=a.concat([c,d.final()])).toString("utf-8");}catch(_err){return e;}}';
      if (js.includes(targetSFn)) {
        js = js.replace(targetSFn, patchedSFn);
      }

      // Smooth quality switching in videojsreadscr.js
      if (js.includes('function initializeVideoPlayer(')) {
        js = js.replace('if (!window.videojs) return;', 'if (!window.videojs) return; try { var existingPlayer = window.videojs.getPlayer ? window.videojs.getPlayer(elementId) : (window.videojs.players ? window.videojs.players[elementId] : null); if (existingPlayer && typeof existingPlayer.src === "function") { console.log("[VideoPlayer] Smooth quality source update:", videoSource); existingPlayer.src(videoSource); existingPlayer.play().catch(function(){}); return; } } catch(err) { console.warn("[VideoPlayer] Existing player update error:", err); }');
        js = js.replace('if (url.uri.includes("ck."))', 'var uriStr = (typeof url === "string") ? url : (url && url.uri ? url.uri : ""); if (uriStr && uriStr.includes("ck."))');
        js = js.replace(/url\.uri\.includes\("ck\."\)\s*\?\s*key_cache\s*:\s*url\.uri/g, 'uriStr.includes("ck.") ? key_cache : uriStr');
      }

      sendResponse(res, upstreamRes.status, responseHeaders, js);
      return;
    }

    // Case 4: Binary Streams, TS chunks, CSS, Images, Video MP4
    sendResponse(res, upstreamRes.status, responseHeaders);
    if (upstreamRes.body) {
      if (typeof res.write === 'function') {
        const stream = typeof upstreamRes.body.pipe === 'function'
          ? upstreamRes.body
          : (typeof Readable.fromWeb === 'function' ? Readable.fromWeb(upstreamRes.body) : null);

        if (stream && typeof stream.pipe === 'function') {
          stream.on('error', (err) => {
            if (!res.writableEnded) {
              try { res.end(); } catch (e) {}
            }
          });
          if (typeof res.on === 'function') {
            res.on('close', () => {
              try { stream.destroy(); } catch (e) {}
            });
          }
          stream.pipe(res);
          return;
        }
      }

      const buffer = await upstreamRes.arrayBuffer();
      res.end(Buffer.from(buffer));
    } else {
      res.end();
    }
  } catch (err) {
    console.error('[Proxy Error]:', err.message);
    sendResponse(res, 502, { 'Content-Type': 'text/plain' }, 'Proxy Error: ' + err.message);
  }
}

async function handleRequest(req, res) {
  if (typeof res.setHeader === 'function') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', '*');
  }

  if (req.method === 'OPTIONS') {
    sendResponse(res, 204, {}, '');
    return;
  }

  const reqUrl = req.url || '/';
  const parsedUrl = new URL(reqUrl, `http://${req.headers.host || 'localhost:' + PORT}`);

  // Handle dummy placeholder images
  if (parsedUrl.pathname.includes('a855f7') || parsedUrl.pathname.includes('placeholder') || parsedUrl.search.includes('No+Image') || parsedUrl.href.includes('No+Image')) {
    sendResponse(res, 200, { 'Content-Type': 'image/png', 'Access-Control-Allow-Origin': '*' }, DUMMY_PNG);
    return;
  }

  // 0. Direct Proxy Endpoint without /proxy?url= (e.g. /https%3A%2F%2F... or /https://...)
  const rawPath = reqUrl.startsWith('/') ? reqUrl.slice(1) : reqUrl;
  if (/^https?[:%]/i.test(rawPath)) {
    let targetUrlStr = rawPath;
    try {
      if (/^https?%/i.test(targetUrlStr)) {
        targetUrlStr = decodeURIComponent(targetUrlStr);
      }
    } catch (e) {}
    await forwardUpstream(targetUrlStr, req, res);
    return;
  }

  // 1. Explicit Proxy Endpoint: /proxy?url=... or /api/proxy?url=...
  const targetUrlStr = parsedUrl.searchParams.get('url') || (req.query && req.query.url);
  if (parsedUrl.pathname === '/proxy' || parsedUrl.pathname === '/api/proxy' || parsedUrl.pathname === '/api/proxy.js') {
    if (!targetUrlStr) {
      sendResponse(res, 400, { 'Content-Type': 'text/plain' }, 'Missing "url" query parameter');
      return;
    }
    await forwardUpstream(targetUrlStr, req, res);
    return;
  }

    // 1.5 List available portal HTML files in root directory
  if (parsedUrl.pathname === '/api/portals') {
    try {
      const files = fs.readdirSync(BASE_DIR);
      const portals = files
        .filter(f => f.toLowerCase().endsWith('.html') && !['appx.html', 'index.html'].includes(f.toLowerCase()))
        .map(f => {
          const rawName = f.replace(/\.html$/i, '');
          return {
            filename: f,
            name: rawName
          };
        });
      sendResponse(res, 200, { 'Content-Type': 'application/json' }, JSON.stringify(portals));
    } catch(err) {
      sendResponse(res, 200, { 'Content-Type': 'application/json' }, JSON.stringify([
        { filename: 'bhainsh.html', name: 'bhainsh' },
        { filename: 'DHYEY.html', name: 'DHYEY' }
      ]));
    }
    return;
  }

  if (parsedUrl.pathname === '/sw.js') {
    sendResponse(res, 200, { 'Content-Type': 'application/javascript' }, '// sw');
    return;
  }

  // 2. UHS HLS Player Scripts & Images proxying (always on appx-play.classx.co.in)
  if (parsedUrl.pathname.startsWith('/uhs-hls-player/')) {
    let cleanPath = parsedUrl.pathname.replace('/images/undefined/', '/images/watermark/');
    const upstreamUrl = 'https://appx-play.classx.co.in' + cleanPath + parsedUrl.search;
    await forwardUpstream(upstreamUrl, req, res);
    return;
  }

  // 3. Next.js chunks & static assets proxying with automatic origin fallback
  if (parsedUrl.pathname.startsWith('/_next/')) {
    const referer = req.headers['referer'] || '';
    let chosenOrigin = currentTargetOrigin;
    if (referer.includes('classx.co.in') || referer.includes('combined-img-player')) {
      chosenOrigin = 'https://appx-play.classx.co.in';
    } else if (referer.includes('player.appx.co.in') || referer.includes('secure-player')) {
      chosenOrigin = 'https://player.appx.co.in';
    }
    const upstreamUrl = chosenOrigin + parsedUrl.pathname + parsedUrl.search;
    await forwardUpstream(upstreamUrl, req, res);
    return;
  }

  // 4. Video player core script fallback
  if (parsedUrl.pathname.startsWith('/videojs-') || parsedUrl.pathname.startsWith('/video-uhs')) {
    const upstreamUrl = 'https://player.appx.co.in' + parsedUrl.pathname + parsedUrl.search;
    await forwardUpstream(upstreamUrl, req, res);
    return;
  }

  // 5. Check if the path matches a local file in workspace
  let safePath = path.normalize(decodeURIComponent(parsedUrl.pathname)).replace(/^(\.\.[\/\\])+/, '');
  if (safePath === '/' || safePath === '\\') {
    safePath = fs.existsSync(path.join(BASE_DIR, 'APPX.html')) ? '/APPX.html' : (fs.existsSync(path.join(BASE_DIR, 'index.html')) ? '/index.html' : '/bhainsh.html');
  }

  const localFilePath = path.join(BASE_DIR, safePath);

  fs.stat(localFilePath, async (err, stats) => {
    if (!err && stats.isFile()) {
      const ext = path.extname(localFilePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      sendResponse(res, 200, { 'Content-Type': contentType });
      fs.createReadStream(localFilePath).pipe(res);
      return;
    }

    // 6. Fallback: Proxy to current target origin
    const upstreamUrl = currentTargetOrigin + parsedUrl.pathname + parsedUrl.search;
    await forwardUpstream(upstreamUrl, req, res);
  });
}

// Global process exception handlers
process.on('uncaughtException', (err) => {
  console.error('[UncaughtException]:', err?.message || err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[UnhandledRejection]:', reason);
});

// Run HTTP server when executed directly via Node.js
if (require.main === module) {
  const server = http.createServer(handleRequest);
  server.listen(PORT, () => {
    console.log(`===================================================`);
    console.log(`🚀 Unified Proxy Server Running on PORT ${PORT}`);
    console.log(`📡 BHAINSH: http://localhost:${PORT}/bhainsh.html`);
    console.log(`📡 DHYEY:   http://localhost:${PORT}/DHYEY.html`);
    console.log(`🔄 Proxy:   http://localhost:${PORT}/proxy?url=`);
    console.log(`===================================================`);
  });
}

module.exports = { handleRequest, forwardUpstream, rewriteM3U8 };

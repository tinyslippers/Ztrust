#!/usr/bin/env python3
"""Web dashboard server for SDN Zero Trust.

Usage:
    cd ~/Bureau/DID
    python3 dashboard_server.py

Access: http://localhost:8080
"""

import json
import os
import subprocess
import threading
import time
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

STATUS_FILE = '/tmp/sdn_auth_status.json'
PIDS_FILE   = '/tmp/mn_host_pids.json'
AGENT_PATH  = '/home/debian/Bureau/Ztrust/DID/agent_auth.py'
PORT = 8181
HTML_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard.html')

# ── Demo Mode ──────────────────────────────────────────────────────
DEMO_SCENARIOS = [
    ( 3,  1, "Client → Serveur Web"),
    ( 5,  1, "Client → Serveur Web"),
    (12,  1, "Client → Serveur Web"),
    (20,  1, "Client → Serveur Web"),
    ( 7,  2, "App → Base de données"),
    ( 9,  2, "App → Base de données"),
    ( 4,  2, "App → Base de données"),
    (14,  3, "Passerelle → DMZ"),
    (16,  8, "Admin → Serveur"),
    (11, 15, "Backup → Stockage"),
    (18,  7, "Supervision → Hôte"),
    ( 6, 19, "Cœur → Périphérie"),
    (22, 10, "Edge → Core"),
    (13, 17, "Intersite A → B"),
    ( 4, 21, "Intersite C → D"),
]
_demo_active = False
_demo_thread = None
_demo_lock   = threading.Lock()
_demo_label  = ''


def _demo_worker():
    global _demo_active, _demo_label
    try:
        with open(PIDS_FILE) as f:
            pids = json.load(f)
    except Exception:
        _demo_active = False
        return

    idx = 0
    while _demo_active:
        src, dst, label = DEMO_SCENARIOS[idx % len(DEMO_SCENARIOS)]
        pid = pids.get(str(src))
        if pid:
            _demo_label = label
            cmd = ['nsenter', '-n', '-t', str(pid), '--',
                   'ping', '-c', '5', '-W', '1', '-i', '0.4', f'10.0.0.{dst}']
            try:
                subprocess.run(cmd, capture_output=True, timeout=10)
            except Exception:
                pass
        idx += 1
        for _ in range(30):   # 3 s pause between pings, interruptible
            if not _demo_active:
                _demo_label = ''
                return
            time.sleep(0.1)
    _demo_label = ''


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


class DashboardHandler(BaseHTTPRequestHandler):

    def log_message(self, *_):
        pass  # Suppress HTTP logs in the terminal

    # ------------------------------------------------------------------
    # GET
    # ------------------------------------------------------------------

    def do_GET(self):
        path = urlparse(self.path).path

        if path == '/':
            self._serve_file()
        elif path == '/vis-network.min.js':
            self._serve_static('vis-network.min.js', 'application/javascript')
        elif path == '/status':
            self._serve_status()
        elif path == '/stream':
            self._serve_sse()
        elif path == '/demo':
            self._send(200, 'application/json',
                       json.dumps({'active': _demo_active,
                                   'label':  _demo_label}).encode(),
                       cors=True)
        elif path == '/ping':
            params = parse_qs(urlparse(self.path).query)
            try:
                src   = int(params['src'][0])
                dst   = int(params['dst'][0])
            except (KeyError, ValueError):
                self._send(400, 'text/plain', b'Parametres src/dst manquants')
                return
            self._serve_ping(src, dst)
        else:
            self._send(404, 'text/plain', b'Not found')

    # ------------------------------------------------------------------
    # POST  /quarantine/<id>  ou  /restore/<id>
    # ------------------------------------------------------------------

    def do_POST(self):
        parts = urlparse(self.path).path.strip('/').split('/')

        if len(parts) == 2 and parts[0] in ('quarantine', 'restore') and parts[1].isdigit():
            sid = parts[1]
            if parts[0] == 'quarantine':
                cmd = ['ovs-vsctl', 'del-controller', f's{sid}']
            else:
                cmd = ['ovs-vsctl', 'set-controller', f's{sid}', 'tcp:127.0.0.1:6633']
            r = subprocess.run(cmd, capture_output=True, text=True)
            self._send(200, 'application/json',
                       json.dumps({'ok': r.returncode == 0,
                                   'msg': r.stderr.strip()}).encode(),
                       cors=True)

        elif parts[0] == 'reauth' and len(parts) == 2 and parts[1].isdigit():
            # Re-auth for a single switch
            ok, msg = self._reauth_switch(int(parts[1]))
            self._send(200, 'application/json',
                       json.dumps({'ok': ok, 'msg': msg}).encode(),
                       cors=True)

        elif parts[0] == 'reauth' and len(parts) == 1:
            # Global re-auth — launched in background to avoid blocking
            threading.Thread(target=self._reauth_all, daemon=True).start()
            self._send(202, 'application/json',
                       json.dumps({'ok': True, 'msg': 'Re-auth globale lancée'}).encode(),
                       cors=True)

        elif parts[0] == 'demo' and len(parts) == 2 and parts[1] in ('start', 'stop'):
            global _demo_active, _demo_thread
            with _demo_lock:
                if parts[1] == 'start' and not _demo_active:
                    _demo_active = True
                    _demo_thread = threading.Thread(target=_demo_worker, daemon=True)
                    _demo_thread.start()
                elif parts[1] == 'stop':
                    _demo_active = False
            self._send(200, 'application/json',
                       json.dumps({'ok': True}).encode(), cors=True)

        else:
            self._send(404, 'text/plain', b'Not found')

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _serve_file(self):
        try:
            with open(HTML_FILE, 'rb') as f:
                body = f.read()
            self._send(200, 'text/html; charset=utf-8', body)
        except FileNotFoundError:
            self._send(404, 'text/plain', b'dashboard.html introuvable')

    def _serve_static(self, filename, ct):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        try:
            with open(path, 'rb') as f:
                body = f.read()
            self._send(200, ct, body)
        except FileNotFoundError:
            self._send(404, 'text/plain', b'Fichier introuvable')

    def _serve_status(self):
        try:
            with open(STATUS_FILE) as f:
                body = f.read().encode()
        except Exception:
            body = b'{}'
        self._send(200, 'application/json', body, cors=True)

    def _serve_sse(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        last = None
        while True:
            try:
                with open(STATUS_FILE) as f:
                    data = f.read()
                if data != last:
                    self.wfile.write(f'data: {data}\n\n'.encode())
                    self.wfile.flush()
                    last = data
            except (BrokenPipeError, ConnectionResetError):
                break
            except Exception:
                pass
            time.sleep(1)

    def _serve_ping(self, src, dst):
        """Runs a continuous ping from the h{src} network namespace to 10.0.0.{dst}, streamed via SSE."""
        dst_ip = f'10.0.0.{dst}'
        try:
            with open(PIDS_FILE) as f:
                pids = json.load(f)
            pid = pids.get(str(src))
            if not pid:
                self._send(400, 'text/plain',
                           f'PID introuvable pour h{src} - Mininet demarre ?'.encode())
                return
        except FileNotFoundError:
            self._send(400, 'text/plain', b'mn_host_pids.json introuvable - lancez topo_projet.py')
            return
        except Exception as e:
            self._send(400, 'text/plain', str(e).encode())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        cmd = ['nsenter', '-n', '-t', str(pid), '--',
               'ping', '-W', '1', '-i', '0.4', dst_ip]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.wfile.write(
                        f'data: {json.dumps({"line": line})}\n\n'.encode())
                    self.wfile.flush()
            proc.wait()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            self.wfile.write(b'data: {"done": true}\n\n')
            self.wfile.flush()
        except Exception:
            pass

    def _reauth_switch(self, sid):
        """Runs agent_auth.py in the h{sid} network namespace via nsenter."""
        try:
            with open(PIDS_FILE) as f:
                pids = json.load(f)
            pid = pids.get(str(sid))
            if not pid:
                return False, f'PID introuvable pour h{sid} (Mininet démarré ?)'
            r = subprocess.run(
                ['nsenter', '-n', '-t', str(pid), '--',
                 'python3', AGENT_PATH, f'switch_{sid}'],
                capture_output=True, text=True, timeout=8
            )
            return r.returncode == 0, r.stderr.strip()
        except FileNotFoundError:
            return False, f'{PIDS_FILE} introuvable — lancez topo_projet.py d\'abord'
        except Exception as e:
            return False, str(e)

    def _reauth_all(self):
        """Re-authenticates all switches sequentially (background thread)."""
        try:
            with open(PIDS_FILE) as f:
                pids = json.load(f)
            for i in range(1, 23):
                pid = pids.get(str(i))
                if pid:
                    subprocess.run(
                        ['nsenter', '-n', '-t', str(pid), '--',
                         'python3', AGENT_PATH, f'switch_{i}'],
                        capture_output=True, timeout=8
                    )
                    time.sleep(0.3)
        except Exception:
            pass

    def _send(self, code, ct, body, cors=False):
        try:
            self.send_response(code)
            self.send_header('Content-Type', ct)
            self.send_header('Content-Length', len(body))
            if cors:
                self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == '__main__':
    server = ThreadingHTTPServer(('0.0.0.0', PORT), DashboardHandler)
    print(f"\n  ╔══════════════════════════════════════╗")
    print(f"  ║  SDN Zero Trust · Dashboard          ║")
    print(f"  ║  http://localhost:{PORT}               ║")
    print(f"  ╚══════════════════════════════════════╝\n")
    print(f"  Lit : {STATUS_FILE}")
    print(f"  Ctrl+C pour arrêter\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard arrêté.")

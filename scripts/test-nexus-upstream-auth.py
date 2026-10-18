#!/usr/bin/env python3
"""Private local qualification against Nexus's fabricated provider harness."""
import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nexus', type=Path, required=True)
    parser.add_argument('--nono', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('owned', args.nexus / 'scripts/spike-owned-broker.py')
    owned = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owned)
    owned.BINARY = args.nexus / 'target/debug/nexus-credential-broker'
    root = Path(tempfile.mkdtemp(prefix='nx-upstream-auth-'))
    for name in ['broker', 'client', 'home', 'state']:
        (root / name).mkdir(mode=0o700)
    current = {'access': 'fabricated-provider-access-0', 'refresh': 'fabricated-provider-refresh-0'}
    hits = {'requests': 0, 'refreshes': 0}
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')

    class Provider(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, value):
            data = json.dumps(value).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            hits['requests'] += 1
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
            if body.get('grant_type') == 'refresh_token':
                assert body['refresh_token'] == current['refresh']
                hits['refreshes'] += 1
                current.update(access='fabricated-provider-access-1', refresh='fabricated-provider-refresh-1')
            token = encode({'alg': 'none'}) + '.' + encode({'https://api.openai.com/auth': {'chatgpt_account_id': 'fixture-account'}}) + '.fixture'
            self.reply({'access_token': current['access'], 'refresh_token': current['refresh'], 'id_token': token, 'token_type': 'Bearer'})

        def do_GET(self):
            if self.headers.get('Upgrade') == 'websocket':
                assert self.headers.get('Authorization') == 'Bearer ' + current['access']
                key = self.headers['Sec-WebSocket-Key']
                accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                self.send_response(101)
                self.send_header('Upgrade', 'websocket')
                self.send_header('Connection', 'Upgrade')
                self.send_header('Sec-WebSocket-Accept', accept)
                self.end_headers()
                frame = self.rfile.read(2)
                length = frame[1] & 127
                mask = self.rfile.read(4)
                payload = self.rfile.read(length)
                payload = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
                self.wfile.write(bytes([0x81, len(payload)]) + payload)
                self.wfile.flush()
                self.close_connection = True
                return
            hits['requests'] += 1
            self.reply({'authenticated': self.headers.get('Authorization') == 'Bearer ' + current['access'],
                        'proxy_authorization_reached_provider': self.headers.get('Proxy-Authorization') is not None})

    provider = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    broker = owned.Harness(root / 'broker', f'http://127.0.0.1:{provider.server_port}')
    env = dict(HOME=str(root / 'home'), XDG_STATE_HOME=str(root / 'state'), PATH='/usr/bin:/bin', LANG='C.UTF-8')
    report = {'nono_sha256': hashlib.sha256(args.nono.read_bytes()).hexdigest(), 'checks': {}}
    captured = []

    def run(command, auth_file, extra=(), success=True, upstream=None):
        value = subprocess.run([str(args.nono), '--silent', 'run', '--workdir', str(root / 'client'),
                                '--allow', str(root / 'client'), '--allow-domain', 'chatgpt.com',
                                '--allow-domain', 'auth.openai.com', '--upstream-proxy', upstream or f'127.0.0.1:{broker.port}',
                                '--upstream-proxy-credential', 'file://' + str(auth_file), *extra, '--', *command],
                               cwd=root / 'client', env=env, capture_output=True, text=True, timeout=30)
        captured.append(value.stdout + value.stderr)
        assert 'fabricated-provider-' not in value.stdout + value.stderr
        if success:
            assert value.returncode == 0, value.stderr[-1500:]
        return value

    def request(auth_file, token=None, body=None):
        target = 'https://auth.openai.com/oauth/token' if body is not None else 'https://chatgpt.com/backend-api/codex/models'
        config = ['silent', 'show-error', 'cacert = "' + str(root / 'client/ca.pem') + '"',
                  'url = "' + target + '"', 'write-out = "\\n%{http_code}"']
        if token:
            config += ['header = "Authorization: Bearer ' + token + '"']
        if body is not None:
            (root / 'client/body.json').write_text(json.dumps(body))
            config += ['header = "Content-Type: application/json"', 'data-binary = "@body.json"']
        (root / 'client/request.conf').write_text('\n'.join(config) + '\n')
        value = run(['/usr/bin/curl', '--config', 'request.conf'], auth_file)
        body, status = value.stdout.strip().rsplit('\n', 1)
        return int(status), body

    try:
        broker.command('init', 'fixture')
        broker.command('certificates')
        broker.command('session', 'a', str(root / 'a.json'))
        first = json.loads((root / 'a.json').read_text())
        auth_a = root / 'auth-a'
        auth_a.write_text('nexus:' + first['proxy_token'])
        auth_a.chmod(0o600)
        (root / 'client/ca.pem').write_bytes((root / 'broker/ca.pem').read_bytes())
        broker.start()
        status, body = request(auth_a, body={'grant_type': 'authorization_code', 'code': 'fabricated-code'})
        assert status == 200
        tokens_a = json.loads(body)
        assert tokens_a['access_token'] != current['access'] and tokens_a['refresh_token'] != current['refresh']
        report['checks']['sandbox_login_receives_only_phantoms'] = True
        status, body = request(auth_a, tokens_a['access_token'])
        assert status == 200 and json.loads(body) == {'authenticated': True, 'proxy_authorization_reached_provider': False}
        report['checks']['authenticated_chain_reaches_broker_without_relay'] = True
        status, body = request(auth_a, body={'grant_type': 'refresh_token', 'refresh_token': tokens_a['refresh_token']})
        assert status == 200 and hits['refreshes'] == 1
        tokens_a = json.loads(body)
        assert tokens_a['refresh_token'] != current['refresh']
        report['checks']['refresh_stays_in_broker_and_returns_phantoms'] = True
        (root / 'client/phantom').write_text(tokens_a['access_token'])
        (root / 'client/ws.py').write_text('import base64, os, socket, ssl, urllib.parse\nfrom pathlib import Path\nproxy=urllib.parse.urlsplit(os.environ.get("HTTPS_PROXY") or os.environ["HTTP_PROXY"])\ns=socket.create_connection((proxy.hostname,proxy.port),timeout=5)\nauth=base64.b64encode((urllib.parse.unquote(proxy.username or "")+":"+urllib.parse.unquote(proxy.password or "")).encode()).decode()\ns.sendall(("CONNECT chatgpt.com:443 HTTP/1.1\\r\\nHost: chatgpt.com:443\\r\\nProxy-Authorization: Basic "+auth+"\\r\\n\\r\\n").encode())\ndef headers(s):\n    data=b""\n    while not data.endswith(b"\\r\\n\\r\\n"):\n        chunk=s.recv(1)\n        assert chunk\n        data+=chunk\n    return data\nassert b" 200 " in headers(s)\ns=ssl.create_default_context(cafile="ca.pem").wrap_socket(s,server_hostname="chatgpt.com")\nkey=base64.b64encode(b"0123456789abcdef").decode()\ns.sendall(("GET /backend-api/codex/responses HTTP/1.1\\r\\nHost: chatgpt.com\\r\\nAuthorization: Bearer "+Path("phantom").read_text()+"\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: "+key+"\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n").encode())\nassert b" 101 " in headers(s)\ns.sendall(bytes([0x81,0x84])+bytes(4)+b"echo")\ndata=b""\nwhile len(data)<6:\n    chunk=s.recv(6-len(data))\n    assert chunk\n    data+=chunk\nassert data==bytes([0x81,4])+b"echo"\ns.close()\nprint("websocket-ok")\n')
        assert run(['/usr/bin/python3', 'ws.py'], auth_a).stdout.strip() == 'websocket-ok'
        report['checks']['websocket_echo_through_authenticated_chain'] = True

        broker.stop()
        broker.command('session', 'b', str(root / 'b.json'))
        second = json.loads((root / 'b.json').read_text())
        auth_b = root / 'auth-b'
        auth_b.write_text('nexus:' + second['proxy_token'])
        auth_b.chmod(0o600)
        broker.start()
        before = hits['requests']
        status, _ = request(auth_a, second['auth']['tokens']['access_token'])
        assert status == 403 and hits['requests'] == before
        report['checks']['cross_session_phantom_rejected_before_provider'] = True

        probe = root / 'client/containment.py'
        probe.write_text('''import os, socket, base64, urllib.parse
from pathlib import Path
paths = %r
for value in paths:
    try:
        Path(value).read_bytes()
    except PermissionError:
        pass
    else:
        raise AssertionError('private file readable')
try:
    socket.create_connection(('127.0.0.1', %d), timeout=2)
except OSError:
    pass
else:
    raise AssertionError('direct broker connection admitted')
# An allowed nonprovider domain can reach the broker TCP port through bypass,
# but cannot turn that tunnel into an authenticated provider route.
p = urllib.parse.urlparse(os.environ['HTTPS_PROXY'])
connection = socket.create_connection((p.hostname, p.port), timeout=3)
credential = base64.b64encode((urllib.parse.unquote(p.username or '')+':'+urllib.parse.unquote(p.password or '')).encode()).decode()
def headers():
    data = b''
    while not data.endswith(b'\\r\\n\\r\\n'):
        part = connection.recv(1)
        if not part:
            break
        data += part
    return data
connection.sendall(('CONNECT localhost:%d HTTP/1.1\\r\\nHost: localhost:%d\\r\\nProxy-Authorization: Basic '+credential+'\\r\\n\\r\\n').encode())
outer = headers()
assert b' 200 ' in outer, outer
connection.sendall(b'CONNECT chatgpt.com:443 HTTP/1.1\\r\\nHost: chatgpt.com:443\\r\\n\\r\\n')
inner = headers()
assert b' 407 ' in inner, inner
print('containment passed')
''' % ([str(auth_a), str(auth_b), str(root / 'broker/store.json')], broker.port, broker.port, broker.port))
        run(['/usr/bin/python3', str(probe)], auth_a, ('--allow-domain', 'localhost', '--upstream-bypass', 'localhost'))
        report['checks']['private_files_direct_broker_and_nested_bypass_denied'] = True

        invalid = root / 'invalid-auth'
        invalid.write_text('nexus:invalid-session-capability')
        invalid.chmod(0o600)
        value = run(['/usr/bin/curl', '-fsS', '--max-time', '5', '--cacert', 'ca.pem', 'https://chatgpt.com/backend-api/codex/models'], invalid, success=False)
        assert value.returncode != 0
        before = hits['requests']
        auth_b.unlink()
        value = run(['/usr/bin/true'], auth_b, success=False)
        assert value.returncode != 0 and hits['requests'] == before
        report['checks']['wrong_and_missing_upstream_credentials_fail_closed'] = True

        seen = []
        class RejectingProxy(socketserver.BaseRequestHandler):
            def handle(self):
                data = b''
                self.request.settimeout(5)
                while not data.endswith(b'\r\n\r\n'):
                    part = self.request.recv(1)
                    if not part:
                        return
                    data += part
                seen.append(data)
                self.request.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n')
        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), RejectingProxy) as mock:
            threading.Thread(target=mock.serve_forever, daemon=True).start()
            value = run(['/usr/bin/curl', '-kfsS', '--max-time', '5', 'https://example.com/path'], auth_a,
                        ('--allow-domain', 'https://example.com/**'), success=False,
                        upstream='127.0.0.1:' + str(mock.server_address[1]))
            mock.shutdown()
        expected = b'Proxy-Authorization: Basic ' + base64.b64encode(auth_a.read_bytes())
        assert seen and all(expected in request for request in seen)
        assert value.returncode != 0
        report['checks']['tls_intercept_sends_auth_and_rejects_upstream_denial'] = True

        broker.command('revoke-live', 'a')
        value = run(['/usr/bin/curl', '-fsS', '--max-time', '5', '--cacert', 'ca.pem', 'https://chatgpt.com/backend-api/codex/models'], auth_a, success=False)
        assert value.returncode != 0
        report['checks']['revoked_session_cannot_reconnect'] = True
        for value in [first['proxy_token'], second['proxy_token'], base64.b64encode(auth_a.read_bytes()).decode()]:
            assert all(value not in output for output in captured)
        report['checks']['no_upstream_capability_in_child_output_or_diagnostics'] = True
    finally:
        broker.stop()
        provider.shutdown()
        report['fixture_root'] = str(root)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

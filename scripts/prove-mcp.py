#!/usr/bin/env python3
"""Synthetic proof through the actual setup-written Codex and Claude configs."""
import http.server
import http.cookies
import json
import os
import pathlib
import queue
import secrets
import socketserver
import subprocess
import threading
import tomllib
import urllib.parse

home = pathlib.Path.home()
outputs = []
passwords = []
sessions = {}
users = {}


class LoopbackServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # A literal loopback fixture has no need for reverse DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'localhost'
        self.server_port = self.server_address[1]


class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        if self.path == '/account':
            cookies = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            session = cookies.get('fixture-session')
            username = sessions.get(session.value) if session else None
            body = f'Signed in as {username}' if username else 'Signed out'
        else:
            body = '<form method="post"><input name="username" autocomplete="username"><input name="password" type="password" autocomplete="current-password"><button type="submit">Continue</button></form>'
        self.wfile.write(body.encode())

    def do_POST(self):
        form = urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
        username = form.get('username', [''])[0]
        password = form.get('password', [''])[0]
        if self.path == '/signup':
            assert username and password
            users[username] = password
            passwords.append(password)
        if users.get(username) != password:
            self.send_error(403)
            return
        session = secrets.token_urlsafe(32)
        sessions[session] = username
        self.send_response(303)
        self.send_header('Set-Cookie', f'fixture-session={session}; HttpOnly; SameSite=Lax; Path=/')
        self.send_header('Location', '/account')
        self.end_headers()


server = LoopbackServer(('127.0.0.1', 0), Fixture)
threading.Thread(target=server.serve_forever, daemon=True).start()
origin = f'http://127.0.0.1:{server.server_port}'
try:
    for name in ['codex', 'claude-code', 'antigravity']:
        if name == 'codex':
            cfg = tomllib.loads((home / '.codex/config.toml').read_text())['mcp_servers']['ralx']
        else:
            path = '.claude.json' if name == 'claude-code' else '.gemini/config/mcp_config.json'
            cfg = json.loads((home / path).read_text())['mcpServers']['ralx']
        process = subprocess.Popen([cfg['command'], *cfg['args']], env={**os.environ, **cfg['env']},
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        replies = queue.Queue()
        errors = []
        def reader():
            for line in process.stdout:
                outputs.append(line)
                replies.put(json.loads(line))
        def err_reader():
            for line in process.stderr:
                errors.append(line)
        read_thread = threading.Thread(target=reader, daemon=True)
        error_thread = threading.Thread(target=err_reader, daemon=True)
        read_thread.start()
        error_thread.start()
        seq = 0
        def send(method, params=None, notify=False):
            global seq
            seq += 1
            request = {'jsonrpc': '2.0', 'method': method}
            if params is not None:
                request['params'] = params
            if not notify:
                request['id'] = seq
            process.stdin.write(json.dumps(request) + '\n')
            process.stdin.flush()
            if notify:
                return
            while True:
                reply = replies.get(timeout=60)
                if reply.get('id') == seq:
                    assert 'error' not in reply, 'MCP request failed'
                    return reply['result']
        def tool(name, args):
            reply = send('tools/call', {'name': name, 'arguments': args})
            assert not reply.get('isError'), f'{name} returned an error'
            for content in reply.get('content', []):
                if content.get('type') == 'text':
                    value = json.loads(content['text'])
                    return value.get('result', value)
            raise AssertionError('Missing MCP tool result')
        try:
            send('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'launch-fixture', 'version': '1'}})
            send('notifications/initialized', notify=True)
            tools = send('tools/list', {})['tools']
            required = {'logins_new_test', 'browser_sign_up', 'browser_sign_in', 'browser_account_text'}
            assert required <= {t['name'] for t in tools}
            print(f'MCP {name}: initialize PASS; tools/list PASS ({len(tools)} tools)', flush=True)
            if name == 'codex':
                created = tool('logins_new_test', {'origin': origin, 'username': 'fixture@example.test'})
                login_id = created['login_id']
                for action, route in [('browser_sign_up', '/signup'), ('browser_sign_in', '/signin')]:
                    result = tool(action, {'url': origin + route, 'login_id': login_id, 'target': 'managed'})
                    assert result.get('status') == 'signed_in', f'{action} did not sign in'
                    print(f'{action}: PASS', flush=True)
                result = tool('browser_account_text', {'login_id': login_id})
                assert result.get('text') == 'Signed in as fixture@example.test'
                print('browser_account_text: PASS', flush=True)
        finally:
            process.stdin.close()
            process.wait(timeout=15)
            read_thread.join(timeout=5)
            error_thread.join(timeout=5)
            outputs.extend(errors)
    service_log = home / '.ralx/setup/service.log'
    if service_log.exists():
        outputs.append(service_log.read_text())
    combined = '\n'.join(outputs)
    assert passwords, 'No password was submitted to the fixture'
    assert len(sessions) >= 2, 'Sign-up and sign-in did not each create a session'
    assert not any(password in combined for password in passwords), 'A fixture password reached an agent reply or log'
    assert not any(session in combined for session in sessions), 'A fixture session cookie reached an agent reply or log'
    print('Fixture passwords in MCP replies, errors and service logs: 0', flush=True)
    print('Fixture session cookies in MCP replies, errors and service logs: 0', flush=True)
finally:
    server.shutdown()
    server.server_close()

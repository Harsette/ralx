#!/bin/sh
# Native macOS proof. All app settings and vault data stay in a throwaway home.
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'This check needs a Mac.' >&2; exit 1; }
binary=${1:?path to the native macOS binary}
shell=${2:-/bin/zsh}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
proof=${RALX_LAUNCH_PROOF_DIR:-$repo/tmp/macos-proof}
mkdir -p "$proof"
echo 'Preparing the Mac install test.'
root=$(mktemp -d /tmp/ralx-macos-proof.XXXXXX)
export HOME="$root/home" USERPROFILE="$root/home"
export APPDATA="$HOME/Library/Application Support" LOCALAPPDATA="$HOME/Library/Caches"
export XDG_CONFIG_HOME="$HOME/.config" SHELL="$shell"
export RALX_SETUP_SANDBOX=1 RALX_SETUP_NO_BROWSER=1
unset RALX_AGENT_KEY RALX_AGENT_KEY_FILE RALX_URL RALX_ADMIN_PIPE CLAUDE_CONFIG_DIR CODEX_HOME RALX_INSTALL_DIR
export RALX_SETUP_ADDR=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print("127.0.0.1:"+str(s.getsockname()[1]));s.close()')
export RALX_SETUP_DATA="$HOME/test-data"
server_pid=''
cleanup() {
  if [ -f "$HOME/.ralx/setup/service.log" ]; then cp "$HOME/.ralx/setup/service.log" "$proof/service.log"; fi
  if [ -e "$HOME/.ralx/setup/state.json" ] && [ -x "$HOME/.local/bin/ralx" ]; then "$HOME/.local/bin/ralx" uninstall || true; fi
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  # This exact directory was created by mktemp above.
  rm -rf "$root"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$root/release" "$HOME"
case "$(uname -m)" in arm64) arch=arm64;; x86_64) arch=amd64;; *) exit 1;; esac
cp "$binary" "$root/release/ralx_darwin_$arch"
cp "$repo/install.sh" "$root/release/install.sh"
(cd "$root/release" && shasum -a 256 "ralx_darwin_$arch" > checksums.txt)
python3 - "$root" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1]);h=root/'home'
paths=['.claude.json','Library/Application Support/Claude/claude_desktop_config.json','.codex/config.toml','.cursor/mcp.json','Library/Application Support/Code/User/mcp.json','.codeium/windsurf/mcp_config.json','.gemini/settings.json','.gemini/config/mcp_config.json']
for p in paths:
 f=h/p;f.parent.mkdir(parents=True,exist_ok=True)
 b=b'# keep exact bytes\r\nmodel="fixture"\r\n[mcp_servers.existing]\r\ncommand="keep"\r\n' if p.endswith('.toml') else json.dumps({'servers' if 'Code/User' in p else 'mcpServers':{'existing':{'command':'keep'}},'keep':True}).encode()
 f.write_bytes(b);(h/(p+'.original')).write_bytes(b)
(h/'.claude').mkdir();(h/'.gemini/antigravity').mkdir()
for p in ['.zprofile','.bash_profile']:
 (h/p).write_bytes(b'# keep this profile exactly\r\n')
(root/'paths.json').write_text(json.dumps(paths))
PY
echo 'Starting the local download server.'
python3 -u - "$root" <<'PY' > "$proof/http.log" 2>&1 &
import http.server, functools, pathlib, socketserver, sys
class ReleaseServer(http.server.ThreadingHTTPServer):
 def server_bind(self):
  # This server only uses literal loopback. Do not wait for reverse DNS.
  socketserver.TCPServer.server_bind(self)
  self.server_name='localhost'; self.server_port=self.server_address[1]
root=pathlib.Path(sys.argv[1]); handler=functools.partial(http.server.SimpleHTTPRequestHandler,directory=str(root/'release'))
print('Binding the local download server.',flush=True)
server=ReleaseServer(('127.0.0.1',0),handler)
(root/'port').write_text(str(server.server_port)); server.serve_forever()
PY
server_pid=$!
i=0
while [ ! -s "$root/port" ]; do
 i=$((i+1))
 if ! kill -0 "$server_pid" 2>/dev/null || [ "$i" -ge 300 ]; then
  echo 'The local download server did not start.' >&2
  cat "$proof/http.log" >&2
  exit 1
 fi
 sleep 0.1
done
echo 'The local download server is ready.'
export RALX_RELEASE_BASE_URL="http://127.0.0.1:$(cat "$root/port")"
# Curl normally writes no quarantine flag. Add one only to this test's downloaded
# binary so the installer's defensive removal is exercised before first launch.
mkdir -p "$root/shims"
cat > "$root/shims/curl" <<'SH'
#!/bin/sh
set -eu
/usr/bin/curl "$@"
dest=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then shift; dest=$1; fi
  shift
done
case "$dest" in */ralx_darwin_*) xattr -w com.apple.quarantine '0081;00000000;RalXFixture;' "$dest";; esac
SH
chmod 755 "$root/shims/curl"
export PATH="$root/shims:$PATH"
curl -fsSL "$RALX_RELEASE_BASE_URL/install.sh" | sh -s -- --mode local --clients all --yes
export PATH="$HOME/.local/bin:$PATH"
echo 'PASS: downloaded the right Mac binary and installed without admin access'
if xattr -p com.apple.quarantine "$HOME/.local/bin/ralx" >/dev/null 2>&1; then echo 'Quarantine was not cleared.' >&2; exit 1; fi
ralx setup --mode local --clients all --yes
ralx doctor
python3 - <<'PY'
import json, os, pathlib, plistlib, subprocess
h=pathlib.Path.home();s=json.loads((h/'.ralx/setup/state.json').read_text())
assert len(s['Clients'])==8,s['Clients']
plist=pathlib.Path(s['Autostart']);p=plistlib.loads(plist.read_bytes())
assert p['RunAtLoad'] and p['EnvironmentVariables']['HOME']==str(h)
uid=os.getuid();domains=[f'gui/{uid}',f'user/{uid}']
assert any(subprocess.run(['launchctl','print',d+'/'+p['Label']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0 for d in domains)
print('PASS: all eight apps connected; launchd plist written and loaded')
PY
# Start a login shell without the installer's PATH. The saved profile must add
# RalX itself, just as it will in the person's next terminal window.
PATH=/usr/bin:/bin:/usr/sbin:/sbin "$SHELL" -lc 'test "$(command -v ralx)" = "$HOME/.local/bin/ralx"'
echo "PASS: PATH works in $SHELL"
python3 "$repo/scripts/prove-mcp.py"
cp "$HOME/.ralx/setup/service.log" "$proof/service.log"
python3 - "$root" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);h=root/'home'
state=json.loads((h/'.ralx/setup/state.json').read_text());plist=pathlib.Path(state['Autostart'])
(root/'autostart-path').write_text(str(plist))
(root/'autostart-label').write_text(__import__('plistlib').loads(plist.read_bytes())['Label'])
PY
ralx uninstall
python3 - "$root" <<'PY'
import json,pathlib,sys,socket,os,subprocess
root=pathlib.Path(sys.argv[1]);h=root/'home'
for p in json.loads((root/'paths.json').read_text()):assert (h/p).read_bytes()==(h/(p+'.original')).read_bytes(),p
for p in ['.zprofile','.bash_profile']:assert (h/p).read_bytes()==b'# keep this profile exactly\r\n',p
assert not (h/'.local/bin/ralx').exists()
assert not pathlib.Path((root/'autostart-path').read_text()).exists()
label=(root/'autostart-label').read_text()
assert all(subprocess.run(['launchctl','print',f'{domain}/{os.getuid()}/'+label],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0 for domain in ['gui','user'])
assert not list(h.rglob('*.ralx-setup.bak'));assert not list(h.rglob('*.ralx-setup.json'));assert not list(h.rglob('*.ralx-path.bak'))
assert not list((h/'.ralx/agents').glob('*.json'))
host,port=os.environ['RALX_SETUP_ADDR'].split(':')
with socket.socket() as sock:assert sock.connect_ex((host,int(port)))!=0
print('PASS: eight configs and both shell profiles restored byte for byte; service, startup and binary removed')
PY

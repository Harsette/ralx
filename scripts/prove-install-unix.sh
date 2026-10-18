#!/bin/sh
# Run in a throwaway Unix home. Argument: absolute path to cross-built Linux binary.
set -eu
source_binary=${1:?absolute path to the built Linux binary}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
root=$(mktemp -d /tmp/ralx-install-proof.XXXXXX)
export HOME="$root/home" USERPROFILE="$root/home"
export APPDATA="$HOME/.config" LOCALAPPDATA="$HOME/.local/share"
export XDG_CONFIG_HOME="$HOME/.config" RALX_SETUP_SANDBOX=1 RALX_SETUP_NO_BROWSER=1
unset RALX_AGENT_KEY RALX_AGENT_KEY_FILE RALX_URL RALX_ADMIN_PIPE CLAUDE_CONFIG_DIR CODEX_HOME RALX_INSTALL_DIR
export RALX_SETUP_ADDR=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print("127.0.0.1:"+str(s.getsockname()[1]));s.close()')
export RALX_SETUP_DATA="$HOME/test-data"
export RALX_RELEASE_BASE_URL="file://$root/release" RALX_SETUP_YES=1
mkdir -p "$root/release" "$HOME"
cleanup() {
  if [ -e "$HOME/.ralx/setup/state.json" ]; then "$HOME/.local/bin/ralx" uninstall || true; fi
  # root is the exact mktemp directory created above, never a user input.
  rm -rf "$root"
}
trap cleanup EXIT HUP INT TERM
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 1;; esac
cp "$source_binary" "$root/release/ralx_linux_$arch"
(cd "$root/release" && sha256sum "ralx_linux_$arch" > checksums.txt)
python3 - <<'PY'
import os,json,pathlib
h=pathlib.Path(os.environ['HOME'])
paths=['.claude.json','.config/Claude/claude_desktop_config.json','.codex/config.toml','.cursor/mcp.json','.config/Code/User/mcp.json','.codeium/windsurf/mcp_config.json','.gemini/settings.json','.gemini/config/mcp_config.json']
for p in paths:
    f=h/p;f.parent.mkdir(parents=True,exist_ok=True)
    if p.endswith('.toml'): b=b'# fixture\nmodel="fixture"\n[mcp_servers.existing]\ncommand="keep"\n'
    else: b=json.dumps({'servers' if 'Code/User' in p else 'mcpServers':{'existing':{'command':'keep'}},'keep':True}).encode()
    f.write_bytes(b);(h/(p+'.original')).write_bytes(b)
(h/'.claude').mkdir()
(h/'.gemini/antigravity').mkdir()
(h/'.profile').write_bytes(b'# preserve this shell profile exactly\n')
PY
sh "$repo/install.sh"
"$HOME/.local/bin/ralx" setup --mode local --clients all --yes --no-browser
"$HOME/.local/bin/ralx" doctor
python3 - <<'PY'
import os,json,pathlib,subprocess,selectors,tomllib
h=pathlib.Path(os.environ['HOME'])
for name in ['codex','claude-code']:
    if name=='codex': cfg=tomllib.loads((h/'.codex/config.toml').read_text())['mcp_servers']['ralx']
    else: cfg=json.loads((h/'.claude.json').read_text())['mcpServers']['ralx']
    p=subprocess.Popen([cfg['command'],*cfg['args']],env={**os.environ,**cfg['env']},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ)
    def send(obj): p.stdin.write(json.dumps(obj)+'\n');p.stdin.flush()
    def receive():
        if not sel.select(15): raise RuntimeError('MCP timeout')
        reply=json.loads(p.stdout.readline())
        assert 'result' in reply,reply
        return reply['result']
    try:
        send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'sandbox','version':'1'}}});receive()
        send({'jsonrpc':'2.0','method':'notifications/initialized'})
        send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}});tools=receive()['tools'];assert tools
        print(f'MCP {name}: initialize OK, tools/list OK ({len(tools)} tools)')
    finally:
        p.stdin.close();p.wait(timeout=10);sel.close()
PY
"$HOME/.local/bin/ralx" setup --remove
"$HOME/.local/bin/ralx" setup --mode local --clients all --yes --no-browser
"$HOME/.local/bin/ralx" uninstall
python3 - <<'PY'
import os,pathlib,socket
h=pathlib.Path(os.environ['HOME'])
originals=list(h.rglob('*.original'));assert len(originals)==8
for f in originals: assert f.read_bytes()==f.with_suffix('').read_bytes(),str(f)
assert not (h/'.local/bin/ralx').exists()
assert not list(h.rglob('*.ralx-setup.bak'))
assert not list(h.rglob('*.ralx-setup.json'))
assert not list((h/'.ralx/agents').glob('*.json'))
assert not (h/'.config/autostart/ralx-user.desktop').exists()
assert not (h/'.config/systemd/user/ralx-user.service').exists()
assert not (h/'.config/systemd/user/default.target.wants/ralx-user.service').is_symlink()
assert (h/'.profile').read_bytes()==b'# preserve this shell profile exactly\n'
assert not (h/'.profile.ralx-path.bak').exists()
host,port=os.environ['RALX_SETUP_ADDR'].split(':')
with socket.socket() as s: assert s.connect_ex((host,int(port)))!=0
print('RESTORED: 8 original configs byte-identical; daemon stopped; identities, autostart, binary and added PATH entry removed; shell profile restored; data retained')
PY

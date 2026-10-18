//go:build windows

package daemon

import (
	"net"
	"os/user"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows/registry"
)

// listenAdmin opens the admin named pipe. Only SYSTEM, *elevated*
// Administrators and the daemon's own account can connect: a normal
// (non-elevated) process, which is what every agent runs as, gets access
// denied. The daemon's own account must be listed so it can create further
// pipe instances; in dev mode that account is the interactive user, which is
// why dev mode is not a security boundary.
func listenAdmin(name string, dev bool) (net.Listener, error) {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if u, err := user.Current(); err == nil {
		sddl += "(A;;GA;;;" + u.Uid + ")"
	}
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl, MessageMode: false, InputBufferSize: 65536, OutputBufferSize: 65536})
}

// uacWarning flags the setting that lets any program silently become admin,
// which would let an agent get around the account boundary.
func uacWarning() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	lua, _, _ := k.GetIntegerValue("EnableLUA")
	consent, _, err := k.GetIntegerValue("ConsentPromptBehaviorAdmin")
	if lua == 0 {
		return "Windows is set to run programs as admin without asking. Turning UAC back to 'Notify me' makes RalX's approvals stronger."
	}
	if err == nil && consent == 0 {
		return "Windows is set to let programs become admin without asking. Turning UAC back to 'Notify me' makes RalX's approvals stronger."
	}
	return ""
}

func defaultToolPaths() map[string][]string {
	return map[string][]string{
		"gh":       {`C:\Program Files\GitHub CLI\gh.exe`},
		"vercel":   {`C:\Program Files\RalX\tools\node\node.exe`, `C:\Program Files\RalX\tools\vercel\node_modules\vercel\dist\index.js`},
		"supabase": {`C:\Program Files\RalX\tools\supabase\supabase.exe`},
		"wrangler": {`C:\Program Files\RalX\tools\node\node.exe`, `C:\Program Files\RalX\tools\wrangler\node_modules\wrangler\bin\wrangler.js`},
	}
}

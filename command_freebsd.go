//go:build freebsd

package jail

import (
	"errors"
	"os/exec"
	"syscall"
)

// Command returns a Cmd that runs inside jail jid. The child calls
// jail_attach(2) after fork, so the calling Go process itself stays on the
// host.
//
// name is not resolved inside the jail: pass an absolute path as seen from
// within it (for example "/bin/sh").
func Command(jid int, name string, arg ...string) *exec.Cmd {
	c := exec.Command(name, arg...)
	if jid <= 0 {
		// SysProcAttr.Jail == 0 means "no jail"; never run on the host by accident.
		c.Err = errors.New("jail: invalid jid")
		return c
	}
	c.SysProcAttr = &syscall.SysProcAttr{Jail: jid}
	return c
}

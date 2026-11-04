//go:build !freebsd

package jail

import "os/exec"

// Command is only functional on FreeBSD; elsewhere the returned Cmd fails
// with ErrUnsupported.
func Command(jid int, name string, arg ...string) *exec.Cmd {
	c := exec.Command(name, arg...)
	c.Err = ErrUnsupported
	return c
}

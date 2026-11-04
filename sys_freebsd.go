//go:build freebsd

package jail

import "syscall"

const errmsgSize = 1024

func cstr(b []byte) string {
	if i := indexNUL(b); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Jail descriptor syscalls (FreeBSD 15). Go's syscall package predates
// them, so the numbers come from sys/kern/syscalls.master.
const (
	sysJailAttachJD = 597
	sysJailRemoveJD = 598
)

func sysAttachJD(fd int) error {
	if _, _, e := syscall.Syscall(sysJailAttachJD, uintptr(fd), 0, 0); e != 0 {
		return &Error{Op: "jail_attach_jd", Errno: e}
	}
	return nil
}

func sysRemoveJD(fd int) error {
	if _, _, e := syscall.Syscall(sysJailRemoveJD, uintptr(fd), 0, 0); e != 0 {
		return &Error{Op: "jail_remove_jd", Errno: e}
	}
	return nil
}

func sysClose(fd int) error { return syscall.Close(fd) }

//go:build freebsd

package jail

import (
	"runtime"
	"syscall"
	"unsafe"
)

const errmsgSize = 1024

func cstr(b []byte) string {
	if i := indexNUL(b); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// iovecs lays out entries as the name/value iovec pairs jail_set(2) and
// jail_get(2) expect, followed by an "errmsg" buffer.
func iovecs(entries []entry, errbuf []byte) []syscall.Iovec {
	iov := make([]syscall.Iovec, 0, 2*len(entries)+2)
	add := func(b []byte, n int) {
		v := syscall.Iovec{}
		if len(b) > 0 {
			v.Base = &b[0]
		}
		v.SetLen(n)
		iov = append(iov, v)
	}
	for _, e := range entries {
		name := append([]byte(e.name), 0)
		add(name, len(name))
		if e.probe {
			add(nil, 0)
		} else {
			add(e.val, len(e.val))
		}
	}
	add(append([]byte("errmsg"), 0), len("errmsg")+1)
	add(errbuf, len(errbuf))
	return iov
}

func jailCall(op string, trap uintptr, entries []entry, flags int) (int, error) {
	errbuf := make([]byte, errmsgSize)
	iov := iovecs(entries, errbuf)
	r, _, e := syscall.Syscall(trap, uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), uintptr(flags))
	runtime.KeepAlive(iov)
	if e != 0 {
		return -1, &Error{Op: op, Errno: e, Msg: cstr(errbuf)}
	}
	// jail_get rewrites iov_len: for probed parameters it is their size, for
	// the others the length actually returned (shorter than the buffer for
	// lists fetched with slack).
	for i, e := range entries {
		n := int(uint64(iov[2*i+1].Len))
		if e.probe {
			entries[i].val = make([]byte, n)
		} else if n < len(e.val) {
			entries[i].val = e.val[:n]
		}
	}
	return int(r), nil
}

func sysSet(entries []entry, flags int) (int, error) {
	return jailCall("jail_set", syscall.SYS_JAIL_SET, entries, flags)
}

func sysGet(entries []entry, flags int) (int, error) {
	return jailCall("jail_get", syscall.SYS_JAIL_GET, entries, flags)
}

func sysAttach(jid int) error {
	if _, _, e := syscall.Syscall(syscall.SYS_JAIL_ATTACH, uintptr(jid), 0, 0); e != 0 {
		return &Error{Op: "jail_attach", Errno: e}
	}
	return nil
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

// cJail is the legacy struct jail, JAIL_API_VERSION 2 (<sys/jail.h>).
type cJail struct {
	version  uint32
	path     *byte
	hostname *byte
	jailname *byte
	ip4s     uint32
	ip6s     uint32
	ip4      *byte
	ip6      *byte
}

func sysLegacyJail(path, hostname, name string, ip4, ip6 []byte) (int, error) {
	cs := func(s string) *byte { return &append([]byte(s), 0)[0] }
	j := cJail{
		version:  2,
		path:     cs(path),
		hostname: cs(hostname),
		ip4s:     uint32(len(ip4) / 4),
		ip6s:     uint32(len(ip6) / 16),
	}
	if name != "" {
		j.jailname = cs(name)
	}
	if len(ip4) > 0 {
		j.ip4 = &ip4[0]
	}
	if len(ip6) > 0 {
		j.ip6 = &ip6[0]
	}
	r, _, e := syscall.Syscall(syscall.SYS_JAIL, uintptr(unsafe.Pointer(&j)), 0, 0)
	runtime.KeepAlive(&j)
	if e != 0 {
		return -1, &Error{Op: "jail", Errno: e}
	}
	return int(r), nil
}

func sysRemove(jid int) error {
	if _, _, e := syscall.Syscall(syscall.SYS_JAIL_REMOVE, uintptr(jid), 0, 0); e != 0 {
		return &Error{Op: "jail_remove", Errno: e}
	}
	return nil
}

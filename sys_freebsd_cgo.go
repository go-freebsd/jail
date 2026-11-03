//go:build freebsd && cgo

package jail

/*
#cgo LDFLAGS: -ljail

#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/jail.h>
#include <netinet/in.h>
#include <errno.h>
#include <jail.h>
#include <stdlib.h>
#include <string.h>

// get selects jail_get(2) over jail_set(2).
static int gj_call(int get, struct iovec *iov, unsigned niov, int flags) {
	return get ? jail_get(iov, niov, flags) : jail_set(iov, niov, flags);
}

// gj_legacy fills the legacy struct jail (JAIL_API_VERSION) and calls jail(2).
static int gj_legacy(const char *path, const char *hostname, const char *name,
    void *ip4, unsigned n4, void *ip6, unsigned n6) {
	struct jail j;

	memset(&j, 0, sizeof(j));
	j.version = JAIL_API_VERSION;
	j.path = (char *)path;
	j.hostname = (char *)hostname;
	j.jailname = (char *)name;
	j.ip4s = n4;
	j.ip6s = n6;
	j.ip4 = ip4;
	j.ip6 = ip6;
	return jail(&j);
}

// gjtype is what libjail's jailparam_init learns about a parameter.
struct gjtype {
	int    ctltype;
	int    kind; // 0 other, 1 bool, 2 jailsys, 3 in_addr, 4 in6_addr
	int    nobool;
	size_t valuelen;
	size_t elemlen;
};

// gj_type returns 0 on success; on failure -1 with errno set by libjail.
static int gj_type(const char *name, struct gjtype *t) {
	struct jailparam jp;

	memset(t, 0, sizeof(*t));
	if (jailparam_init(&jp, name) < 0)
		return -1;
	t->ctltype = jp.jp_ctltype;
	t->valuelen = jp.jp_valuelen;
	t->elemlen = jp.jp_elemlen;
	t->nobool = (jp.jp_flags & JP_NOBOOL) != 0;
	if (jp.jp_flags & JP_BOOL)
		t->kind = 1;
	else if (jp.jp_flags & JP_JAILSYS)
		t->kind = 2;
	else if (jp.jp_structtype == JPS_IN_ADDR)
		t->kind = 3;
	else if (jp.jp_structtype == JPS_IN6_ADDR)
		t->kind = 4;
	jailparam_free(&jp, 1);
	return 0;
}
*/
import "C"

import (
	"syscall"
	"unsafe"
)

// libjail backend: libc's jail system call wrappers, and libjail's
// jailparam_init for parameter types.

func init() { resolver = resolveFromLibjail }

func errnoOf(err error) syscall.Errno {
	if e, ok := err.(syscall.Errno); ok {
		return e
	}
	return syscall.EINVAL
}

// jailCall runs jail_set (get == false) or jail_get on entries. Everything the
// kernel sees is copied into C memory, because a C array of iovecs may not
// hold Go pointers. For jail_get the values are copied back.
func jailCall(op string, get bool, entries []entry, flags int) (int, error) {
	n := 2*len(entries) + 2
	iov := (*C.struct_iovec)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.struct_iovec{}))))
	defer C.free(unsafe.Pointer(iov))
	vec := unsafe.Slice(iov, n)

	var bufs []unsafe.Pointer
	defer func() {
		for _, p := range bufs {
			C.free(p)
		}
	}()
	// add stores b[:size] as vec[i]; size 0 is a NULL base (probe, or empty).
	add := func(i int, b []byte, size int) unsafe.Pointer {
		vec[i].iov_len = C.size_t(size)
		if size == 0 {
			return nil
		}
		p := C.calloc(1, C.size_t(size))
		if len(b) > 0 {
			copy(unsafe.Slice((*byte)(p), size), b[:size])
		}
		bufs = append(bufs, p)
		vec[i].iov_base = p
		return p
	}

	data := make([]unsafe.Pointer, len(entries))
	for i, e := range entries {
		name := append([]byte(e.name), 0)
		add(2*i, name, len(name))
		if !e.probe {
			data[i] = add(2*i+1, e.val, len(e.val))
		}
	}
	errName := append([]byte("errmsg"), 0)
	add(n-2, errName, len(errName))
	errBuf := add(n-1, nil, errmsgSize)

	g := C.int(0)
	if get {
		g = 1
	}
	r, err := C.gj_call(g, iov, C.uint(n), C.int(flags))
	if r < 0 {
		return -1, &Error{Op: op, Errno: errnoOf(err), Msg: C.GoString((*C.char)(errBuf))}
	}
	// jail_get rewrites iov_len: for probed parameters it is their size, for
	// the others the length actually returned.
	for i, e := range entries {
		l := int(vec[2*i+1].iov_len)
		switch {
		case e.probe:
			entries[i].val = make([]byte, l)
		case get && data[i] != nil:
			if l > len(e.val) {
				l = len(e.val)
			}
			copy(e.val, unsafe.Slice((*byte)(data[i]), l))
			entries[i].val = e.val[:l]
		}
	}
	return int(r), nil
}

func sysSet(entries []entry, flags int) (int, error) {
	return jailCall("jail_set", false, entries, flags)
}

func sysGet(entries []entry, flags int) (int, error) {
	return jailCall("jail_get", true, entries, flags)
}

func sysAttach(jid int) error {
	if r, err := C.jail_attach(C.int(jid)); r < 0 {
		return &Error{Op: "jail_attach", Errno: errnoOf(err)}
	}
	return nil
}

func sysRemove(jid int) error {
	if r, err := C.jail_remove(C.int(jid)); r < 0 {
		return &Error{Op: "jail_remove", Errno: errnoOf(err)}
	}
	return nil
}

func sysLegacyJail(path, hostname, name string, ip4, ip6 []byte) (int, error) {
	cPath, cHost := C.CString(path), C.CString(hostname)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cHost))
	var cName *C.char
	if name != "" {
		cName = C.CString(name)
		defer C.free(unsafe.Pointer(cName))
	}
	var p4, p6 unsafe.Pointer
	if len(ip4) > 0 {
		p4 = unsafe.Pointer(&ip4[0])
	}
	if len(ip6) > 0 {
		p6 = unsafe.Pointer(&ip6[0])
	}
	r, err := C.gj_legacy(cPath, cHost, cName, p4, C.uint(len(ip4)/4), p6, C.uint(len(ip6)/16))
	if r < 0 {
		return -1, &Error{Op: "jail", Errno: errnoOf(err)}
	}
	return int(r), nil
}

// resolveFromLibjail answers the resolver contract from jailparam_init, which
// consults the kernel itself. libjail does not expose the sysctl format
// string, so a stand-in carrying what parseType looks at is synthesised.
func resolveFromLibjail(name string) (uint32, string, int, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	var t C.struct_gjtype
	if r, err := C.gj_type(cName, &t); r < 0 {
		return 0, "", 0, errnoOf(err)
	}
	if t.nobool != 0 {
		// "allow.noraw_sockets": let the caller resolve the positive form and
		// mark it negated, as it does for the sysctl backend.
		return 0, "", 0, syscall.ENOENT
	}
	var format string
	switch t.kind {
	case 1:
		format = "B"
	case 2:
		format = "E,jailsys"
	case 3:
		format = "S,in_addr"
	case 4:
		format = "S,in6_addr"
	}
	if t.elemlen != 0 && format != "" {
		format += ",a"
	}
	strLen := 0
	if uint32(t.ctltype)&ctlMask == ctlString {
		strLen = int(t.valuelen)
		if strLen == 0 && (name == "meta" || name == "env") {
			format = "A,keyvalue"
		}
	}
	return uint32(t.ctltype), format, strLen, nil
}

//go:build freebsd

package jail

import (
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	paramPrefix = "security.jail.param"

	// The "sysctl" meta-MIB, <sys/sysctl.h>.
	ctlSysctl       = 0
	sysctlName      = 1 // OID -> name
	sysctlNext      = 2 // next OID
	sysctlName2OID  = 3 // name -> OID
	sysctlOIDFmt    = 4 // OID's kind and format
	ctlMaxName      = 24
	maxOIDBytes     = ctlMaxName * 4
	sysctlMaxRetry  = 5
	sysctlSlackSize = 16
)

func init() { resolver = resolveFromSysctl }

// sysctl is a raw __sysctl(2) call. With old == nil it reports the size
// needed.
func sysctl(mib []int32, old, newp []byte) (int, error) {
	var oldp, newpp unsafe.Pointer
	oldlen := uintptr(len(old))
	if len(old) > 0 {
		oldp = unsafe.Pointer(&old[0])
	}
	if len(newp) > 0 {
		newpp = unsafe.Pointer(&newp[0])
	}
	_, _, e := syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(oldp), uintptr(unsafe.Pointer(&oldlen)),
		uintptr(newpp), uintptr(len(newp)))
	if e != 0 {
		return 0, e
	}
	return int(oldlen), nil
}

// sysctlGet reads a value of unknown size.
func sysctlGet(mib []int32) ([]byte, error) {
	for i := 0; i < sysctlMaxRetry; i++ {
		n, err := sysctl(mib, nil, nil)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, n+sysctlSlackSize)
		n, err = sysctl(mib, buf, nil)
		if err == syscall.ENOMEM { // grew in between
			continue
		}
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	return nil, syscall.ENOMEM
}

func oidsFrom(b []byte) []int32 {
	oid := make([]int32, len(b)/4)
	for i := range oid {
		oid[i] = int32(binary.NativeEndian.Uint32(b[4*i:]))
	}
	return oid
}

func meta(op int32, oid []int32) []int32 {
	return append([]int32{ctlSysctl, op}, oid...)
}

func name2oid(name string) ([]int32, error) {
	buf := make([]byte, maxOIDBytes)
	n, err := sysctl([]int32{ctlSysctl, sysctlName2OID}, buf, []byte(name))
	if err != nil {
		return nil, err
	}
	return oidsFrom(buf[:n]), nil
}

func oidName(oid []int32) (string, error) {
	b, err := sysctlGet(meta(sysctlName, oid))
	if err != nil {
		return "", err
	}
	return cstr(b), nil
}

func nextOID(oid []int32) ([]int32, error) {
	buf := make([]byte, maxOIDBytes)
	n, err := sysctl(meta(sysctlNext, oid), buf, nil)
	if err != nil {
		return nil, err
	}
	return oidsFrom(buf[:n]), nil
}

func oidFmt(oid []int32) (kind uint32, format string, err error) {
	b, err := sysctlGet(meta(sysctlOIDFmt, oid))
	if err != nil {
		return 0, "", err
	}
	if len(b) < 4 {
		return 0, "", syscall.EINVAL
	}
	return binary.NativeEndian.Uint32(b), cstr(b[4:]), nil
}

// emptyChild finds the empty-named child that describes a node parameter
// such as "ip4", named "security.jail.param.<name>.". Every candidate is
// verified by its name, so a wrong guess about the OID layout is harmless.
func emptyChild(oid []int32, name string) ([]int32, error) {
	want := paramPrefix + "." + name + "."
	check := func(cand []int32) bool {
		got, err := oidName(cand)
		return err == nil && got == want
	}
	// By name, with the trailing dot selecting the empty component.
	if cand, err := name2oid(want); err == nil && check(cand) {
		return cand, nil
	}
	last := oid[len(oid)-1]
	for _, d := range []int32{-1, 1} {
		// A neighbour of the node.
		sib := slices.Clone(oid)
		sib[len(sib)-1] = last + d
		if check(sib) {
			return sib, nil
		}
		// A child numbered next to the node's own number (libjail's probe).
		if child := append(slices.Clone(oid), last+d); check(child) {
			return child, nil
		}
	}
	// The node's first descendant in tree order.
	if next, err := nextOID(oid); err == nil && check(next) {
		return next, nil
	}
	return nil, syscall.ENOENT
}

// resolveFromSysctl is libjail's jailparam_type: kind, format and, for
// strings, the maximum length (published as a decimal string value).
func resolveFromSysctl(name string) (uint32, string, int, error) {
	oid, err := name2oid(paramPrefix + "." + name)
	if err != nil {
		return 0, "", 0, err
	}
	kind, format, err := oidFmt(oid)
	if err != nil {
		return 0, "", 0, err
	}
	if kind&ctlMask == ctlNode {
		if leaf, err := emptyChild(oid, name); err == nil {
			if k, f, err := oidFmt(leaf); err == nil {
				oid, kind, format = leaf, k, f
			}
		}
	}
	strLen := 0
	if kind&ctlMask == ctlString {
		if v, err := sysctlGet(oid); err == nil {
			strLen, _ = strconv.Atoi(strings.TrimSpace(cstr(v)))
		}
	}
	return kind, format, strLen, nil
}

// listParamNames walks security.jail.param, like libjail's jailparam_all.
func listParamNames() ([]string, error) {
	base, err := name2oid(paramPrefix)
	if err != nil {
		return nil, err
	}
	var names []string
	for cur := base; ; {
		next, err := nextOID(cur)
		if errors.Is(err, syscall.ENOENT) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(next) <= len(base) || !slices.Equal(next[:len(base)], base) {
			break
		}
		cur = next
		name, err := oidName(cur)
		if err != nil {
			return nil, err
		}
		names = append(names, strings.TrimPrefix(name, paramPrefix+"."))
	}
	return names, nil
}

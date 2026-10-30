package jail

import (
	"errors"
	"math/bits"
	"strings"
	"sync"
	"syscall"
)

// class is the broad kind of a jail parameter.
type class uint8

const (
	clString class = iota
	clInt
	clBool
	clIP4
	clIP6
	clNode        // structural sysctl node, not a parameter
	clUnsupported // struct or array type we cannot encode
)

// ptype describes how a parameter is laid out in a jail_set/jail_get iovec.
type ptype struct {
	class   class
	size    int  // scalar size in bytes; for strings the maximum length
	elem    int  // element size of an array (IP address lists)
	signed  bool // integers
	array   bool
	noBool  bool   // the name is the "no" form of a boolean
	jailsys bool   // inherit/new/disable integer
	format  string // raw sysctl format, kept to explain unsupported types
}

// sysctl kind values, from <sys/sysctl.h>.
const (
	ctlMask   = 0xf
	ctlNode   = 1
	ctlInt    = 2
	ctlString = 3
	ctlS64    = 4
	ctlOpaque = 5
	ctlUint   = 6
	ctlLong   = 7
	ctlUlong  = 8
	ctlU64    = 9
	ctlU8     = 0xa
	ctlU16    = 0xb
	ctlS8     = 0xc
	ctlS16    = 0xd
	ctlS32    = 0xe
	ctlU32    = 0xf
)

// longSize is sizeof(long) on every FreeBSD architecture (LP64 or ILP32).
const longSize = bits.UintSize / 8

const (
	defaultStringLen   = 1024
	defaultKeyValueLen = 4096
)

// parseType maps a sysctl kind and format string, as libjail's
// jailparam_type does, to a parameter type. strLen is the maximum string
// length the kernel reported (0 if unknown).
func parseType(ctl uint32, format string, strLen int) ptype {
	t := ptype{format: format}
	base := strings.TrimSuffix(format, ",a")
	array := base != format

	intType := func(size int, signed bool) ptype {
		t.class, t.size, t.signed = clInt, size, signed
		return t
	}
	switch ctl & ctlMask {
	case ctlNode:
		t.class = clNode
	case ctlInt:
		t = intType(4, true)
		switch base {
		case "B":
			t.class = clBool
		case "E,jailsys":
			t.jailsys = true
		}
	case ctlUint, ctlU32:
		t = intType(4, false)
	case ctlS32:
		t = intType(4, true)
	case ctlLong:
		t = intType(longSize, true)
	case ctlUlong:
		t = intType(longSize, false)
	case ctlS64:
		t = intType(8, true)
	case ctlU64:
		t = intType(8, false)
	case ctlS8:
		t = intType(1, true)
	case ctlU8:
		t = intType(1, false)
	case ctlS16:
		t = intType(2, true)
	case ctlU16:
		t = intType(2, false)
	case ctlString:
		t.class = clString
		t.size = strLen
		if t.size <= 0 {
			t.size = defaultStringLen
			if strings.Contains(base, "keyvalue") {
				t.size = defaultKeyValueLen
			}
		}
	case ctlOpaque:
		switch base {
		case "S,in_addr":
			t.class, t.elem, t.array = clIP4, 4, true
		case "S,in6_addr":
			t.class, t.elem, t.array = clIP6, 16, true
		default:
			t.class = clUnsupported
		}
		return t
	default:
		t.class = clUnsupported
		return t
	}
	if array {
		// Arrays of anything but addresses are not supported.
		t.class, t.array = clUnsupported, true
	}
	return t
}

func intT(size int, signed bool) ptype { return ptype{class: clInt, size: size, signed: signed} }
func sysT() ptype                      { return ptype{class: clInt, size: 4, signed: true, jailsys: true} }

var (
	boolT = ptype{class: clBool, size: 4}
	ip4T  = ptype{class: clIP4, elem: 4, array: true}
	ip6T  = ptype{class: clIP6, elem: 16, array: true}
)

// staticTypes covers the stock parameters. It is the fallback when the
// kernel cannot be asked (and the only source off FreeBSD).
var staticTypes = map[string]ptype{
	"jid":                intT(4, true),
	"lastjid":            intT(4, true),
	"desc":               intT(4, true),
	"parent":             intT(4, true),
	"securelevel":        intT(4, true),
	"children.max":       intT(4, true),
	"children.cur":       intT(4, true),
	"enforce_statfs":     intT(4, true),
	"devfs_ruleset":      intT(4, true),
	"cpuset.id":          intT(4, true),
	"osreldate":          intT(4, true),
	"vnet":               sysT(),
	"host":               sysT(),
	"ip4":                sysT(),
	"ip6":                sysT(),
	"sysvmsg":            sysT(),
	"sysvsem":            sysT(),
	"sysvshm":            sysT(),
	"host.hostid":        intT(longSize, false),
	"persist":            boolT,
	"dying":              boolT,
	"ip4.saddrsel":       boolT,
	"ip6.saddrsel":       boolT,
	"zfs.mount_snapshot": boolT,
	"ip4.addr":           ip4T,
	"ip6.addr":           ip6T,
}

func staticType(name string) ptype {
	if strings.HasPrefix(name, "allow.") {
		return boolT
	}
	if t, ok := staticTypes[name]; ok {
		return t
	}
	size := defaultStringLen
	if name == "meta" || name == "env" {
		size = defaultKeyValueLen
	}
	return ptype{class: clString, size: size}
}

// resolver asks the kernel for a parameter's sysctl kind, format and (for
// strings) maximum length. It is set by the FreeBSD build; with nil the
// static table is used. An ENOENT error means "no such parameter".
var resolver func(name string) (ctl uint32, format string, strLen int, err error)

var typeCache = struct {
	sync.RWMutex
	m map[string]ptype
}{m: map[string]ptype{}}

// typeOf returns the type of a parameter, from the kernel when possible.
// Unknown parameters fail with a *ParamError wrapping ErrUnknownParam.
func typeOf(name string) (ptype, error) {
	// Pseudo-parameters have no sysctl.
	if name == "lastjid" || name == "desc" || resolver == nil {
		return staticType(name), nil
	}
	typeCache.RLock()
	t, ok := typeCache.m[name]
	typeCache.RUnlock()
	if ok {
		return t, nil
	}
	t, cacheable, err := resolveType(name)
	if err == nil && cacheable {
		typeCache.Lock()
		typeCache.m[name] = t
		typeCache.Unlock()
	}
	return t, err
}

func resolveType(name string) (t ptype, cacheable bool, err error) {
	ctl, format, n, err := resolver(name)
	if err == nil {
		t := parseType(ctl, format, n)
		if st, ok := staticTypes[name]; ok && t.class == clNode {
			// A group (ip4, vnet...) whose describing child could not be
			// found: the built-in definition is better than "node".
			return st, false, nil
		}
		return t, true, nil
	}
	if !errors.Is(err, syscall.ENOENT) {
		// Discovery is unavailable (not "no such parameter"): degrade to
		// the static table without caching the guess.
		return staticType(name), false, nil
	}
	// A boolean may only exist in its positive form: allow.noraw_sockets.
	if base, ok := stripNo(name); ok {
		if ctl, format, n, err := resolver(base); err == nil {
			if t := parseType(ctl, format, n); t.class == clBool {
				t.noBool = true
				return t, true, nil
			}
		}
	}
	return ptype{}, false, &ParamError{Name: name, Err: ErrUnknownParam}
}

// stripNo turns the "no" form of a boolean name into the positive form:
// nopersist -> persist, allow.noraw_sockets -> allow.raw_sockets.
func stripNo(name string) (string, bool) {
	i := strings.LastIndexByte(name, '.')
	rest := name[i+1:]
	if len(rest) > 2 && strings.HasPrefix(rest, "no") {
		return name[:i+1] + rest[2:], true
	}
	return "", false
}

// ParamInfo describes a jail parameter as the kernel defines it.
type ParamInfo struct {
	Name string
	// Type is one of "string", "int", "uint", "bool", "jailsys", "ipv4",
	// "ipv6", "node" or "unsupported".
	Type string
	// Size is the byte size of a scalar, the maximum length of a string, or
	// the element size of an address list.
	Size int
	// Array reports a variable-length list.
	Array bool
	// Format is the raw sysctl format string, when known.
	Format string
}

func (t ptype) info(name string) ParamInfo {
	pi := ParamInfo{Name: name, Size: t.size, Array: t.array, Format: t.format}
	switch t.class {
	case clString:
		pi.Type = "string"
	case clInt:
		switch {
		case t.jailsys:
			pi.Type = "jailsys"
		case t.signed:
			pi.Type = "int"
		default:
			pi.Type = "uint"
		}
	case clBool:
		pi.Type = "bool"
	case clIP4:
		pi.Type, pi.Size = "ipv4", t.elem
	case clIP6:
		pi.Type, pi.Size = "ipv6", t.elem
	case clNode:
		pi.Type = "node"
	default:
		pi.Type = "unsupported"
	}
	return pi
}

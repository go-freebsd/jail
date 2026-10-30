package jail

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Values for the "ip4", "ip6", "vnet", "host" and sysv* parameters.
const (
	SysDisable = 0
	SysNew     = 1
	SysInherit = 2
)

// Params is a set of jail parameters keyed by their kernel name, as listed
// by `sysctl security.jail.param` (or ListParams). Their types are taken
// from the kernel, so parameters added by modules or newer releases work.
//
// Accepted Go types per parameter type:
//
//	string          string
//	integers        any Go integer type whose value fits the parameter
//	jailsys         the above, or "disable", "new", "inherit"
//	bool            bool
//	ip4.addr        netip.Addr or []netip.Addr (IPv4)
//	ip6.addr        netip.Addr or []netip.Addr (IPv6)
//
// Values returned by Get use string, bool, []netip.Addr and, for integers,
// int (signed up to 32 bits), int64, uint32 (unsigned up to 32 bits) or
// uint64.
type Params map[string]any

// entry is one name/value pair of a jail_set/jail_get iovec array.
type entry struct {
	name string
	val  []byte
	// probe asks the kernel for the value's size instead of its content
	// (jail_get only, for variable-length parameters).
	probe bool
	// elem is the element size of a probed array, used to leave slack for
	// elements added between the probe and the fetch.
	elem int
}

// negate turns a boolean name into its "no" form: persist -> nopersist,
// allow.raw_sockets -> allow.noraw_sockets.
func negate(name string) string {
	i := strings.LastIndexByte(name, '.')
	return name[:i+1] + "no" + name[i+1:]
}

// encode converts p into jail_set entries, sorted by name.
func encode(p Params) ([]entry, error) {
	names := make([]string, 0, len(p))
	for n := range p {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]entry, 0, len(names))
	for _, n := range names {
		e, err := encodeOne(n, p[n])
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func encodeOne(name string, v any) (entry, error) {
	t, err := typeOf(name)
	if err != nil {
		return entry{}, err
	}
	bad := func() (entry, error) {
		return entry{}, fmt.Errorf("jail: parameter %q: unsupported value %v (%T)", name, v, v)
	}
	switch t.class {
	case clString:
		s, ok := v.(string)
		if !ok {
			return bad()
		}
		return entry{name: name, val: append([]byte(s), 0)}, nil

	case clInt:
		if d, ok := v.(*Desc); ok && name == "desc" {
			v = d.fd
		}
		if s, ok := v.(string); ok && t.jailsys {
			switch s {
			case "disable":
				v = SysDisable
			case "new":
				v = SysNew
			case "inherit":
				v = SysInherit
			}
		}
		b, ok := packInt(v, t.size, t.signed)
		if !ok {
			return bad()
		}
		return entry{name: name, val: b}, nil

	case clBool:
		b, ok := v.(bool)
		if !ok {
			return bad()
		}
		// Booleans are flags: the name alone (no value) means true, the
		// "no" form means false. A parameter known only by its "no" name
		// is the other way round.
		if !b {
			if t.noBool {
				name, _ = stripNo(name)
			} else {
				name = negate(name)
			}
		}
		return entry{name: name}, nil

	case clIP4, clIP6:
		var addrs []netip.Addr
		switch x := v.(type) {
		case netip.Addr:
			addrs = []netip.Addr{x}
		case []netip.Addr:
			addrs = x
		default:
			return bad()
		}
		b, ok := packAddrs(addrs, t.class == clIP4)
		if !ok {
			return bad()
		}
		return entry{name: name, val: b}, nil
	}
	return entry{}, unsupported(name, t)
}

func unsupported(name string, t ptype) error {
	if t.class == clNode {
		return fmt.Errorf("jail: %q is a parameter group, not a parameter", name)
	}
	return fmt.Errorf("jail: parameter %q: unsupported type (sysctl format %q)", name, t.format)
}

// packAddrs flattens addrs into the in_addr / in6_addr array layout.
// It fails if any address is invalid or of the wrong family.
func packAddrs(addrs []netip.Addr, want4 bool) ([]byte, bool) {
	var b []byte
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || a.Is4() != want4 {
			return nil, false
		}
		b = append(b, a.AsSlice()...)
	}
	return b, true
}

// packInt encodes any Go integer into size native-endian bytes, rejecting
// values outside the range of the (un)signed target.
func packInt(v any, size int, signed bool) ([]byte, bool) {
	neg, mag, ok := splitInt(v)
	if !ok {
		return nil, false
	}
	bitsN := uint(size * 8)
	var val uint64
	if signed {
		limit := uint64(1) << (bitsN - 1)
		if neg {
			if mag > limit {
				return nil, false
			}
			val = -mag // two's complement
		} else {
			if mag > limit-1 {
				return nil, false
			}
			val = mag
		}
	} else {
		if neg && mag != 0 {
			return nil, false
		}
		if bitsN < 64 && mag > 1<<bitsN-1 {
			return nil, false
		}
		val = mag
	}
	b := make([]byte, size)
	switch size {
	case 1:
		b[0] = byte(val)
	case 2:
		binary.NativeEndian.PutUint16(b, uint16(val))
	case 4:
		binary.NativeEndian.PutUint32(b, uint32(val))
	case 8:
		binary.NativeEndian.PutUint64(b, val)
	default:
		return nil, false
	}
	return b, true
}

// splitInt returns the sign and magnitude of any Go integer.
func splitInt(v any) (neg bool, mag uint64, ok bool) {
	s := func(x int64) (bool, uint64, bool) {
		if x < 0 {
			return true, -uint64(x), true
		}
		return false, uint64(x), true
	}
	switch x := v.(type) {
	case int:
		return s(int64(x))
	case int8:
		return s(int64(x))
	case int16:
		return s(int64(x))
	case int32:
		return s(int64(x))
	case int64:
		return s(x)
	case uint:
		return false, uint64(x), true
	case uint8:
		return false, uint64(x), true
	case uint16:
		return false, uint64(x), true
	case uint32:
		return false, uint64(x), true
	case uint64:
		return false, x, true
	}
	return false, 0, false
}

// readEntry returns the jail_get entry that requests parameter name.
func readEntry(name string) (entry, error) {
	t, err := typeOf(name)
	if err != nil {
		return entry{}, err
	}
	switch t.class {
	case clIP4, clIP6:
		return entry{name: name, probe: true, elem: t.elem}, nil
	case clInt, clBool:
		return entry{name: name, val: make([]byte, t.size)}, nil
	case clString:
		return entry{name: name, val: make([]byte, t.size)}, nil
	}
	return entry{}, unsupported(name, t)
}

func readUint(b []byte, size int) uint64 {
	switch size {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.NativeEndian.Uint16(b))
	case 4:
		return uint64(binary.NativeEndian.Uint32(b))
	}
	return binary.NativeEndian.Uint64(b)
}

// decode converts the value the kernel returned for name.
func decode(name string, b []byte) (any, error) {
	t, err := typeOf(name)
	if err != nil {
		return nil, err
	}
	short := func(n int) (any, error) {
		return nil, fmt.Errorf("jail: parameter %q: short value (%d bytes, need %d)", name, len(b), n)
	}
	switch t.class {
	case clString:
		if i := indexNUL(b); i >= 0 {
			b = b[:i]
		}
		return string(b), nil

	case clInt:
		if len(b) < t.size {
			return short(t.size)
		}
		u := readUint(b, t.size)
		if !t.signed {
			if t.size == 8 {
				return u, nil
			}
			return uint32(u), nil
		}
		shift := uint(64 - t.size*8)
		i := int64(u<<shift) >> shift // sign-extend
		if t.size == 8 {
			return i, nil
		}
		return int(i), nil

	case clBool:
		if len(b) < t.size {
			return short(t.size)
		}
		return readUint(b, t.size) != 0, nil

	case clIP4, clIP6:
		if len(b)%t.elem != 0 {
			return short(t.elem)
		}
		addrs := make([]netip.Addr, 0, len(b)/t.elem)
		for ; len(b) > 0; b = b[t.elem:] {
			a, _ := netip.AddrFromSlice(b[:t.elem])
			addrs = append(addrs, a)
		}
		return addrs, nil
	}
	return nil, unsupported(name, t)
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

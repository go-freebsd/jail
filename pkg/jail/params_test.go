package jail

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	p := Params{
		"name":              "web",
		"securelevel":       3,
		"persist":           true,
		"allow.raw_sockets": false,
		"host.hostname":     "x",
		"ip4.addr":          []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
		"host.hostid":       uint64(7),
	}
	es, err := encode(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	var order []string
	for _, e := range es {
		got[e.name] = e.val
		order = append(order, e.name)
	}
	want := []string{"allow.noraw_sockets", "host.hostid", "host.hostname", "ip4.addr", "name", "persist", "securelevel"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("names/order = %v, want %v", order, want)
	}
	if string(got["name"]) != "web\x00" {
		t.Errorf("name = %q", got["name"])
	}
	if len(got["persist"]) != 0 || len(got["allow.noraw_sockets"]) != 0 {
		t.Error("bool flags must have empty values")
	}
	if binary.NativeEndian.Uint32(got["securelevel"]) != 3 || len(got["securelevel"]) != 4 {
		t.Errorf("securelevel = %v", got["securelevel"])
	}
	if !reflect.DeepEqual(got["ip4.addr"], []byte{10, 0, 0, 1, 10, 0, 0, 2}) {
		t.Errorf("ip4.addr = %v", got["ip4.addr"])
	}
	if len(got["host.hostid"]) != longSize {
		t.Errorf("host.hostid len = %d", len(got["host.hostid"]))
	}
}

func TestEncodeErrors(t *testing.T) {
	for name, p := range map[string]Params{
		"string wants string": {"name": 1},
		"int overflow":        {"securelevel": int64(1) << 40},
		"bool wants bool":     {"persist": "yes"},
		"v6 in ip4":           {"ip4.addr": netip.MustParseAddr("::1")},
		"negative ulong":      {"host.hostid": -1},
	} {
		if _, err := encode(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestNegate(t *testing.T) {
	for in, want := range map[string]string{
		"persist":           "nopersist",
		"allow.mount.devfs": "allow.mount.nodevfs",
		"ip4.saddrsel":      "ip4.nosaddrsel",
	} {
		if got := negate(in); got != want {
			t.Errorf("negate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecode(t *testing.T) {
	v, _ := decode("name", []byte("web\x00garbage"))
	if v != "web" {
		t.Errorf("string = %v", v)
	}
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, 5)
	if v, _ := decode("jid", b); v != 5 {
		t.Errorf("int = %v", v)
	}
	if v, _ := decode("persist", b); v != true {
		t.Errorf("bool = %v", v)
	}
	v, _ = decode("ip6.addr", netip.MustParseAddr("fd00::1").AsSlice())
	if !reflect.DeepEqual(v, []netip.Addr{netip.MustParseAddr("fd00::1")}) {
		t.Errorf("ip6 = %v", v)
	}
	if _, err := decode("jid", []byte{1}); err == nil {
		t.Error("short int should fail")
	}
}

func TestReadEntrySizes(t *testing.T) {
	if e, _ := readEntry("ip4.addr"); !e.probe || e.elem != 4 {
		t.Error("ip4.addr must be probed with 4-byte elements")
	}
	if e, _ := readEntry("jid"); len(e.val) != 4 {
		t.Error("jid buffer must be 4 bytes")
	}
	if e, _ := readEntry("allow.chflags"); len(e.val) != 4 {
		t.Error("bool buffer must be 4 bytes")
	}
}

func TestPackAddrs(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("fd00::1")
	if b, ok := packAddrs([]netip.Addr{v4}, true); !ok || !reflect.DeepEqual(b, []byte{192, 0, 2, 1}) {
		t.Errorf("v4 = %v %v", b, ok)
	}
	if b, ok := packAddrs([]netip.Addr{v6}, false); !ok || len(b) != 16 {
		t.Errorf("v6 = %v %v", b, ok)
	}
	if _, ok := packAddrs([]netip.Addr{v6}, true); ok {
		t.Error("v6 accepted as v4")
	}
	if _, ok := packAddrs([]netip.Addr{{}}, true); ok {
		t.Error("zero Addr accepted")
	}
}

func TestDescParam(t *testing.T) {
	es, err := encode(Params{"desc": &Desc{fd: 7}})
	if err != nil || len(es) != 1 || binary.NativeEndian.Uint32(es[0].val) != 7 {
		t.Fatalf("desc encode = %v, %v", es, err)
	}
	if _, err := encode(Params{"jid": &Desc{fd: 7}}); err == nil {
		t.Error("*Desc must only be accepted for \"desc\"")
	}
}

func TestSetRejectsDescOutputConflict(t *testing.T) {
	if _, err := Set(FlagGetDesc, Params{"desc": 3}); err == nil {
		t.Error("desc input with FlagGetDesc must fail")
	}
}

func TestLegacyJailValidation(t *testing.T) {
	if _, err := LegacyJail(LegacySpec{}); err == nil {
		t.Error("empty path must fail")
	}
	bad := LegacySpec{Path: "/", IP4: []netip.Addr{netip.MustParseAddr("::1")}}
	if _, err := LegacyJail(bad); err == nil {
		t.Error("v6 in IP4 must fail")
	}
}

func TestFlagValues(t *testing.T) {
	// <sys/jail.h>
	for f, want := range map[Flags]int{
		FlagCreate: 0x01, FlagUpdate: 0x02, FlagAttach: 0x04, FlagDying: 0x08,
		FlagUseDesc: 0x10, FlagAtDesc: 0x20, FlagGetDesc: 0x40, FlagOwnDesc: 0x80,
	} {
		if int(f) != want {
			t.Errorf("flag %#x, want %#x", int(f), want)
		}
	}
}

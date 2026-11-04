package jail

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"syscall"
	"testing"
)

func TestParseType(t *testing.T) {
	for _, c := range []struct {
		name   string
		ctl    uint32
		format string
		strLen int
		want   ptype
	}{
		{"int", ctlInt, "I", 0, ptype{class: clInt, size: 4, signed: true, format: "I"}},
		{"bool", ctlInt, "B", 0, ptype{class: clBool, size: 4, signed: true, format: "B"}},
		{"jailsys", ctlInt, "E,jailsys", 0, ptype{class: clInt, size: 4, signed: true, jailsys: true, format: "E,jailsys"}},
		{"uint", ctlUint, "IU", 0, ptype{class: clInt, size: 4, format: "IU"}},
		{"long", ctlLong, "L", 0, ptype{class: clInt, size: longSize, signed: true, format: "L"}},
		{"ulong", ctlUlong, "LU", 0, ptype{class: clInt, size: longSize, format: "LU"}},
		{"s64", ctlS64, "Q", 0, ptype{class: clInt, size: 8, signed: true, format: "Q"}},
		{"u8", ctlU8, "CU", 0, ptype{class: clInt, size: 1, format: "CU"}},
		{"s16", ctlS16, "S", 0, ptype{class: clInt, size: 2, signed: true, format: "S"}},
		{"string sized", ctlString, "A", 256, ptype{class: clString, size: 256, format: "A"}},
		{"string unsized", ctlString, "A", 0, ptype{class: clString, size: defaultStringLen, format: "A"}},
		{"keyvalue unsized", ctlString, "A,keyvalue", 0, ptype{class: clString, size: defaultKeyValueLen, format: "A,keyvalue"}},
		{"ip4", ctlOpaque, "S,in_addr,a", 0, ptype{class: clIP4, elem: 4, array: true, format: "S,in_addr,a"}},
		{"ip6", ctlOpaque, "S,in6_addr,a", 0, ptype{class: clIP6, elem: 16, array: true, format: "S,in6_addr,a"}},
		{"ip4 without suffix", ctlOpaque, "S,in_addr", 0, ptype{class: clIP4, elem: 4, array: true, format: "S,in_addr"}},
		{"mac", ctlOpaque, "S,mac", 0, ptype{class: clUnsupported, format: "S,mac"}},
		{"node", ctlNode, "N", 0, ptype{class: clNode, format: "N"}},
		{"int array", ctlInt, "I,a", 0, ptype{class: clUnsupported, size: 4, signed: true, array: true, format: "I,a"}},
	} {
		if got := parseType(c.ctl, c.format, c.strLen); got != c.want {
			t.Errorf("%s: parseType = %+v, want %+v", c.name, got, c.want)
		}
	}
}

type fakeEntry struct {
	ctl    uint32
	format string
	strLen int
}

// withResolver installs a fake kernel for the test and clears the cache.
func withResolver(t *testing.T, params map[string]fakeEntry, calls *int) {
	t.Helper()
	old := resolver
	resolver = func(name string) (uint32, string, int, error) {
		if calls != nil {
			*calls++
		}
		e, ok := params[name]
		if !ok {
			return 0, "", 0, syscall.ENOENT
		}
		return e.ctl, e.format, e.strLen, nil
	}
	reset := func() {
		typeCache.Lock()
		typeCache.m = map[string]ptype{}
		typeCache.Unlock()
	}
	reset()
	t.Cleanup(func() { resolver = old; reset() })
}

var fakeKernel = map[string]fakeEntry{
	"name":          {ctlString, "A", 256},
	"securelevel":   {ctlInt, "I", 0},
	"allow.chflags": {ctlInt, "B", 0},
	"vnet":          {ctlInt, "E,jailsys", 0},
	"host.hostid":   {ctlUlong, "LU", 0},
	"cpus":          {ctlU32, "IU", 0},
	"small":         {ctlS8, "C", 0},
	"ip4.addr":      {ctlOpaque, "S,in_addr,a", 0},
	"mac.label":     {ctlOpaque, "S,mac", 0},
	"allow":         {ctlNode, "N", 0},
	"linux.osname":  {ctlString, "A", 64},
	"future.value":  {ctlU64, "QU", 0},
}

func TestTypeOfDiscoversFromKernel(t *testing.T) {
	withResolver(t, fakeKernel, nil)

	// Not in the static table: only discovery knows it.
	pi, err := DescribeParam("future.value")
	if err != nil || pi.Type != "uint" || pi.Size != 8 {
		t.Errorf("future.value = %+v, %v", pi, err)
	}
	pi, _ = DescribeParam("linux.osname")
	if pi.Type != "string" || pi.Size != 64 {
		t.Errorf("linux.osname = %+v", pi)
	}
	// Discovery overrides a static guess (static says string for unknown).
	pi, _ = DescribeParam("cpus")
	if pi.Type != "uint" {
		t.Errorf("cpus = %+v", pi)
	}
	if pi, _ := DescribeParam("allow"); pi.Type != "node" {
		t.Errorf("allow = %+v", pi)
	}
	if pi, _ := DescribeParam("mac.label"); pi.Type != "unsupported" || pi.Format != "S,mac" {
		t.Errorf("mac.label = %+v", pi)
	}
}

func TestUnknownParameter(t *testing.T) {
	withResolver(t, fakeKernel, nil)

	_, err := encode(Params{"bogus.x": "1"})
	var pe *ParamError
	if !errors.As(err, &pe) || pe.Name != "bogus.x" || !errors.Is(err, ErrUnknownParam) {
		t.Fatalf("err = %v, want ParamError/ErrUnknownParam", err)
	}
	// List relies on ENOENT meaning "no more jails"; never confuse the two.
	if errors.Is(err, syscall.ENOENT) {
		t.Error("unknown parameter must not match ENOENT")
	}
	if _, err := readEntry("bogus.x"); !errors.Is(err, ErrUnknownParam) {
		t.Errorf("readEntry err = %v", err)
	}
}

func TestTypeCache(t *testing.T) {
	calls := 0
	withResolver(t, fakeKernel, &calls)
	for i := 0; i < 5; i++ {
		if _, err := typeOf("securelevel"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("resolver called %d times for a cached parameter, want 1", calls)
	}
	typeOf("bogus")
	typeOf("bogus")
	if calls < 3 {
		t.Errorf("failures must not be cached (calls = %d)", calls)
	}
}

func TestResolverErrorFallsBackToStatic(t *testing.T) {
	old := resolver
	resolver = func(string) (uint32, string, int, error) { return 0, "", 0, syscall.EPERM }
	typeCache.Lock()
	typeCache.m = map[string]ptype{}
	typeCache.Unlock()
	t.Cleanup(func() { resolver = old })

	tt, err := typeOf("ip4.addr")
	if err != nil || tt.class != clIP4 {
		t.Fatalf("typeOf = %+v, %v; want static ip4", tt, err)
	}
	typeCache.RLock()
	n := len(typeCache.m)
	typeCache.RUnlock()
	if n != 0 {
		t.Error("a static fallback must not be cached as if discovered")
	}
}

func TestNoFormBoolean(t *testing.T) {
	withResolver(t, fakeKernel, nil)

	tt, err := typeOf("allow.nochflags")
	if err != nil || !tt.noBool || tt.class != clBool {
		t.Fatalf("typeOf = %+v, %v", tt, err)
	}
	es, _ := encode(Params{"allow.nochflags": true})
	if es[0].name != "allow.nochflags" || len(es[0].val) != 0 {
		t.Errorf("true = %+v", es[0])
	}
	es, _ = encode(Params{"allow.nochflags": false})
	if es[0].name != "allow.chflags" {
		t.Errorf("false = %+v", es[0])
	}
	// The plain form still negates normally.
	es, _ = encode(Params{"allow.chflags": false})
	if es[0].name != "allow.nochflags" {
		t.Errorf("plain false = %+v", es[0])
	}
	// "no" form of something that is not a boolean is unknown.
	if _, err := typeOf("nosecurelevel"); !errors.Is(err, ErrUnknownParam) {
		t.Errorf("nosecurelevel: %v", err)
	}
}

func TestEncodeDecodeDiscovered(t *testing.T) {
	withResolver(t, fakeKernel, nil)

	es, err := encode(Params{"vnet": "new", "securelevel": int8(-1), "cpus": uint32(7), "future.value": uint64(1) << 40})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for _, e := range es {
		got[e.name] = e.val
	}
	if binary.NativeEndian.Uint32(got["vnet"]) != SysNew {
		t.Errorf("vnet = %v", got["vnet"])
	}
	if int32(binary.NativeEndian.Uint32(got["securelevel"])) != -1 {
		t.Errorf("securelevel = %v", got["securelevel"])
	}
	if binary.NativeEndian.Uint64(got["future.value"]) != 1<<40 {
		t.Errorf("future.value = %v", got["future.value"])
	}

	for name, c := range map[string]struct {
		raw  []byte
		want any
	}{
		"securelevel":  {[]byte{0xff, 0xff, 0xff, 0xff}, -1},
		"cpus":         {[]byte{7, 0, 0, 0}, uint32(7)},
		"small":        {[]byte{0xff}, -1},
		"future.value": {got["future.value"], uint64(1) << 40},
	} {
		if name == "securelevel" || name == "cpus" {
			// raw bytes above are little endian; build native.
			v := binary.LittleEndian.Uint32(c.raw)
			b := make([]byte, 4)
			binary.NativeEndian.PutUint32(b, v)
			c.raw = b
		}
		v, err := decode(name, c.raw)
		if err != nil || v != c.want {
			t.Errorf("decode(%s) = %v (%T), %v; want %v (%T)", name, v, v, err, c.want, c.want)
		}
	}
}

func TestEncodeRejects(t *testing.T) {
	withResolver(t, fakeKernel, nil)
	for name, p := range map[string]Params{
		"s8 overflow":       {"small": 128},
		"s8 underflow":      {"small": -129},
		"uint negative":     {"cpus": -1},
		"uint overflow":     {"cpus": uint64(1) << 32},
		"bad jailsys":       {"vnet": "bogus"},
		"node is not param": {"allow": true},
		"mac unsupported":   {"mac.label": "x"},
	} {
		if _, err := encode(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := readEntry("mac.label"); err == nil {
		t.Error("reading an unsupported type must fail")
	}
}

func TestStaticFallbackWithoutResolver(t *testing.T) {
	if resolver != nil {
		t.Skip("running on FreeBSD")
	}
	// Unknown names stay strings off FreeBSD: nothing to ask.
	if _, err := encode(Params{"whatever": "x"}); err != nil {
		t.Error(err)
	}
}

// --- array sizing with slop and retry ---

func newArrayFake(sizes []int, actual int) (getFunc, *[]string) {
	var log []string
	probeN := 0
	get := func(entries []entry, flags int) (int, error) {
		for i, e := range entries {
			if !e.probe {
				continue
			}
			log = append(log, "probe")
			n := sizes[min(probeN, len(sizes)-1)]
			probeN++
			entries[i].val = make([]byte, n)
			return 0, nil
		}
		log = append(log, "fetch")
		arr := entries[1]
		if len(arr.val) < actual {
			return -1, &Error{Op: "jail_get", Errno: syscall.EINVAL}
		}
		for i := 0; i < actual; i++ {
			arr.val[i] = byte(i)
		}
		entries[1].val = arr.val[:actual] // what the sys layer does with iov_len
		return 7, nil
	}
	return get, &log
}

func arrayEntries() []entry {
	return []entry{{name: "jid", val: make([]byte, 4)}, {name: "ip4.addr", probe: true, elem: 4}}
}

func TestGetWithRetryGrowsAndTrims(t *testing.T) {
	// Probe says 8 bytes, but by fetch time the list has 36: slop (20) is
	// not enough, so the first fetch fails and sizing is repeated.
	get, log := newArrayFake([]int{8, 36}, 36)
	es := arrayEntries()
	jid, err := getWithRetry(get, 1, es, 0)
	if err != nil || jid != 7 {
		t.Fatalf("jid = %d, err = %v", jid, err)
	}
	if want := []string{"probe", "fetch", "probe", "fetch"}; !reflect.DeepEqual(*log, want) {
		t.Errorf("calls = %v, want %v", *log, want)
	}
	if len(es[1].val) != 36 {
		t.Errorf("value not trimmed to the returned length: %d", len(es[1].val))
	}
}

func TestGetWithRetrySlopAvoidsRetry(t *testing.T) {
	// One address appears after the probe: slop absorbs it.
	get, log := newArrayFake([]int{8}, 12)
	es := arrayEntries()
	if _, err := getWithRetry(get, 1, es, 0); err != nil {
		t.Fatal(err)
	}
	if want := []string{"probe", "fetch"}; !reflect.DeepEqual(*log, want) {
		t.Errorf("calls = %v, want %v", *log, want)
	}
	if len(es[1].val) != 12 {
		t.Errorf("len = %d, want 12", len(es[1].val))
	}
}

func TestGetWithRetryGivesUp(t *testing.T) {
	get, log := newArrayFake([]int{8}, 1<<20) // never fits
	_, err := getWithRetry(get, 1, arrayEntries(), 0)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("err = %v, want EINVAL", err)
	}
	fetches := 0
	for _, c := range *log {
		if c == "fetch" {
			fetches++
		}
	}
	if fetches != arraySanity+1 {
		t.Errorf("fetches = %d, want %d", fetches, arraySanity+1)
	}
}

func TestGetWithRetryKernelMessageIsFinal(t *testing.T) {
	calls := 0
	get := func(entries []entry, flags int) (int, error) {
		calls++
		if entries[1].probe {
			entries[1].val = make([]byte, 4)
			return 0, nil
		}
		return -1, &Error{Op: "jail_get", Errno: syscall.EINVAL, Msg: "no jail specified"}
	}
	_, err := getWithRetry(get, 1, arrayEntries(), 0)
	var je *Error
	if !errors.As(err, &je) || je.Msg != "no jail specified" {
		t.Fatalf("err = %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, an EINVAL with a message must not be retried", calls)
	}
}

func TestGetWithRetryNeverCreatesDescriptorWhileSizing(t *testing.T) {
	var probeFlags, fetchFlags int
	get := func(entries []entry, flags int) (int, error) {
		if entries[len(entries)-1].probe {
			probeFlags = flags
			entries[len(entries)-1].val = make([]byte, 4)
			return 0, nil
		}
		fetchFlags = flags
		return 3, nil
	}
	es := []entry{{name: "jid", val: make([]byte, 4)}, {name: "ip4.addr", probe: true, elem: 4}}
	if _, err := getWithRetry(get, 1, es, FlagGetDesc|FlagDying); err != nil {
		t.Fatal(err)
	}
	if probeFlags != int(FlagDying) || fetchFlags != int(FlagGetDesc|FlagDying) {
		t.Errorf("probe flags %#x, fetch flags %#x", probeFlags, fetchFlags)
	}
}

func TestGetWithRetryNoArraysIsSingleCall(t *testing.T) {
	calls := 0
	get := func([]entry, int) (int, error) { calls++; return 1, nil }
	if _, err := getWithRetry(get, 1, []entry{{name: "jid", val: make([]byte, 4)}}, 0); err != nil || calls != 1 {
		t.Errorf("calls = %d, err = %v", calls, err)
	}
}

func TestIPDecodeUsesReturnedLength(t *testing.T) {
	v, err := decode("ip4.addr", []byte{10, 0, 0, 1})
	if err != nil || !reflect.DeepEqual(v, []netip.Addr{netip.MustParseAddr("10.0.0.1")}) {
		t.Errorf("decode = %v, %v", v, err)
	}
}

func TestNodeFallsBackToStaticWhenChildNotFound(t *testing.T) {
	withResolver(t, map[string]fakeEntry{"ip4": {ctlNode, "N", 0}, "allow": {ctlNode, "N", 0}}, nil)

	tt, err := typeOf("ip4")
	if err != nil || tt.class != clInt || !tt.jailsys {
		t.Errorf("ip4 = %+v, %v; want the static jailsys definition", tt, err)
	}
	if tt, _ := typeOf("allow"); tt.class != clNode {
		t.Errorf("a group without a static entry stays a node: %+v", tt)
	}
}

func TestQueryNeverRepeatsASelector(t *testing.T) {
	old := doGet
	t.Cleanup(func() { doGet = old })
	var sent []string
	doGet = func(entries []entry, flags int) (int, error) {
		sent = nil
		for _, e := range entries {
			sent = append(sent, e.name)
		}
		for i, e := range entries {
			if e.name == "host.hostname" {
				copy(entries[i].val, "h.test\x00")
			}
		}
		return 9, nil
	}

	lookup, _ := encode(Params{"jid": 9})
	p, jid, _, err := query(0, lookup, []string{"jid", "name", "host.hostname"})
	if err != nil || jid != 9 {
		t.Fatalf("jid = %d, err = %v", jid, err)
	}
	count := map[string]int{}
	for _, n := range sent {
		count[n]++
	}
	if count["jid"] != 1 {
		t.Errorf("jid sent %d times (%v): it would replace the selector", count["jid"], sent)
	}
	if p["jid"] != 9 || p["host.hostname"] != "h.test" {
		t.Errorf("result = %v", p)
	}

	// Selecting by name and asking for the name back is answered locally.
	lookup, _ = encode(Params{"name": "web"})
	p, _, _, err = query(0, lookup, []string{"name", "jid"})
	if err != nil || p["name"] != "web" || p["jid"] != 9 {
		t.Errorf("by name = %v, %v", p, err)
	}
	count = map[string]int{}
	for _, n := range sent {
		count[n]++
	}
	if count["name"] != 1 {
		t.Errorf("name sent %d times: %v", count["name"], sent)
	}
}

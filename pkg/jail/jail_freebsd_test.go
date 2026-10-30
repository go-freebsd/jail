//go:build freebsd

package jail

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests need root (jail_set requires PRIV_JAIL_SET), so they skip
// otherwise. CI runs them as root in a FreeBSD VM.

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

// Jail descriptors arrived in FreeBSD 15.0 (__FreeBSD_version 1500000).
func needDescriptors(t *testing.T) {
	t.Helper()
	v, err := syscall.SysctlUint32("kern.osreldate")
	if err != nil {
		t.Fatalf("kern.osreldate: %v", err)
	}
	if v < 1500000 {
		t.Skipf("jail descriptors need FreeBSD 15 (osreldate %d)", v)
	}
}

// create makes a persistent jail and removes it when the test ends.
func create(t *testing.T, name, path string, extra Params) int {
	t.Helper()
	p := Params{"name": name, "path": path}
	for k, v := range extra {
		p[k] = v
	}
	jid, err := Create(p)
	if err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
	t.Cleanup(func() { _ = Remove(jid) })
	return jid
}

func TestLifecycle(t *testing.T) {
	needRoot(t)
	const name = "gojail_test"

	jid := create(t, name, t.TempDir(), Params{
		"host.hostname": "gojail.test",
		"securelevel":   2,
		"allow.chflags": true,
		"ip4.addr":      []netip.Addr{netip.MustParseAddr("127.0.1.1")},
	})

	if got, err := Lookup(name); err != nil || got != jid {
		t.Fatalf("Lookup = %d, %v; want %d", got, err, jid)
	}

	p, err := Get(jid, "name", "host.hostname", "securelevel", "allow.chflags", "persist", "ip4.addr")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	t.Logf("Get: %v", p)
	if p["name"] != name || p["host.hostname"] != "gojail.test" ||
		p["securelevel"] != 2 || p["allow.chflags"] != true || p["persist"] != true {
		t.Errorf("unexpected params: %v", p)
	}
	if ips, _ := p["ip4.addr"].([]netip.Addr); len(ips) != 1 || ips[0].String() != "127.0.1.1" {
		t.Errorf("ip4.addr = %v", p["ip4.addr"])
	}

	if err := Update(Params{"jid": jid, "host.hostname": "renamed.test"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if p, _ := GetByName(name, "host.hostname"); p["host.hostname"] != "renamed.test" {
		t.Errorf("hostname after Update = %v", p)
	}

	infos, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, i := range infos {
		t.Logf("List: %+v", i)
		found = found || i.JID == jid
	}
	if !found {
		t.Errorf("jail %d not in List", jid)
	}

	if err := Remove(jid); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Lookup(name); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lookup after Remove: %v, want not-exist", err)
	}
}

func TestErrorCarriesKernelMessage(t *testing.T) {
	needRoot(t)
	_, err := Create(Params{"name": "gojail_bad", "path": "/nonexistent/dir"})
	var je *Error
	if !errors.As(err, &je) {
		t.Fatalf("err = %v, want *Error", err)
	}
	t.Logf("kernel said: %v", je)
	if je.Msg == "" {
		t.Error("expected the kernel's errmsg text")
	}
}

// Dying jails: a jail with a process in it that is removed lingers as dying.
// Only checks the flag is accepted and the result is a superset of List().
func TestListDying(t *testing.T) {
	needRoot(t)
	live, err := List()
	if err != nil {
		t.Fatal(err)
	}
	all, err := ListDying()
	if err != nil {
		t.Fatalf("ListDying: %v", err)
	}
	if len(all) < len(live) {
		t.Errorf("ListDying (%d) < List (%d)", len(all), len(live))
	}
}

// Command runs the child inside the jail (jail root is the host's /, so
// /bin and /sbin exist there).
func TestCommand(t *testing.T) {
	needRoot(t)
	jid := create(t, "gojail_cmd", "/", Params{"host.hostname": "cmd.test"})

	out, err := Command(jid, "/bin/hostname").Output()
	if err != nil || strings.TrimSpace(string(out)) != "cmd.test" {
		t.Errorf("hostname in jail = %q, %v", out, err)
	}
	out, err = Command(jid, "/sbin/sysctl", "-n", "security.jail.jailed").Output()
	if err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Errorf("security.jail.jailed in jail = %q, %v", out, err)
	}
	if err := Command(0, "/bin/true").Run(); err == nil {
		t.Error("jid 0 must be refused, not run on the host")
	}
}

// --- calls that confine the calling process run in a re-exec'd helper ---

// helper re-runs this test binary in the given mode and returns its output.
func helper(t *testing.T, mode string, env ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(append(os.Environ(), "GOJAIL_HELPER="+mode), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %s: %v\n%s", mode, err, out)
	}
	return string(out)
}

func jailed() bool {
	v, err := syscall.SysctlUint32("security.jail.jailed")
	return err == nil && v == 1
}

func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("GOJAIL_HELPER")
	if mode == "" {
		t.Skip("helper only")
	}
	fail := func(err error) {
		fmt.Printf("FAIL %s: %v\n", mode, err)
		os.Exit(1)
	}
	var jid int
	var err error
	switch mode {
	case "attach": // jail_attach(2)
		fmt.Sscan(os.Getenv("GOJAIL_JID"), &jid)
		err = Attach(jid)
	case "attach_jd": // jail_attach_jd(2)
		fmt.Sscan(os.Getenv("GOJAIL_JID"), &jid)
		var d *Desc
		if d, err = OpenDesc(jid, false); err == nil {
			err = d.Attach()
		}
	case "legacy": // jail(2)
		jid, err = LegacyJail(LegacySpec{Path: "/", Hostname: "legacy.test", Name: "gojail_legacy"})
	case "create_attach": // jail_set(2) with JAIL_CREATE|JAIL_ATTACH
		jid, err = CreateAttach(Params{"name": "gojail_ca", "path": "/", "host.hostname": "ca.test"})
	default:
		fail(fmt.Errorf("unknown mode"))
	}
	if err != nil {
		fail(err)
	}
	if !jailed() {
		fail(errors.New("security.jail.jailed != 1 after confining call"))
	}
	host, _ := syscall.Sysctl("kern.hostname")
	fmt.Printf("OK jid=%d hostname=%s\n", jid, host)
	os.Exit(0)
}

func TestAttach(t *testing.T) {
	needRoot(t)
	jid := create(t, "gojail_attach", t.TempDir(), nil)
	t.Log(helper(t, "attach", fmt.Sprintf("GOJAIL_JID=%d", jid)))
}

func TestLegacyJail(t *testing.T) {
	needRoot(t)
	out := helper(t, "legacy")
	t.Log(out)
	if !strings.Contains(out, "hostname=legacy.test") {
		t.Errorf("legacy jail hostname not applied: %s", out)
	}
}

func TestCreateAttach(t *testing.T) {
	needRoot(t)
	out := helper(t, "create_attach")
	t.Log(out)
	if !strings.Contains(out, "hostname=ca.test") {
		t.Errorf("hostname not applied: %s", out)
	}
}

// --- jail descriptors (FreeBSD 15+) ---

func TestDescriptors(t *testing.T) {
	needRoot(t)
	needDescriptors(t)

	res, err := CreateDesc(Params{"name": "gojail_desc", "path": t.TempDir(), "host.hostname": "d.test"}, false)
	if err != nil {
		t.Fatalf("CreateDesc: %v", err)
	}
	t.Cleanup(func() { _ = Remove(res.JID) })
	d := res.Desc
	if d == nil || d.Fd() < 0 {
		t.Fatalf("no descriptor returned: %+v", res)
	}
	defer d.Close()

	p, err := d.Get("jid", "name", "host.hostname")
	if err != nil || p["jid"] != res.JID || p["name"] != "gojail_desc" {
		t.Fatalf("Desc.Get = %v, %v (jid %d)", p, err, res.JID)
	}
	if err := d.Update(Params{"host.hostname": "d2.test"}); err != nil {
		t.Fatalf("Desc.Update: %v", err)
	}
	if p, _ := d.Get("host.hostname"); p["host.hostname"] != "d2.test" {
		t.Errorf("hostname after Desc.Update = %v", p)
	}

	d2, err := OpenDesc(res.JID, false)
	if err != nil {
		t.Fatalf("OpenDesc: %v", err)
	}
	if p, _ := d2.Get("jid"); p["jid"] != res.JID {
		t.Errorf("OpenDesc refers to wrong jail: %v", p)
	}
	d2.Close()

	// jail_attach_jd in a helper process.
	t.Log(helper(t, "attach_jd", fmt.Sprintf("GOJAIL_JID=%d", res.JID)))

	// jail_remove_jd
	if err := d.Remove(); err != nil {
		t.Fatalf("Desc.Remove: %v", err)
	}
	if _, err := Lookup("gojail_desc"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lookup after Desc.Remove: %v, want not-exist", err)
	}
	if err := d.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Errorf("second Close must be a no-op: %v", err)
	}
}

func TestOwningDescriptor(t *testing.T) {
	needRoot(t)
	needDescriptors(t)

	res, err := CreateDesc(Params{"name": "gojail_own", "path": t.TempDir()}, true)
	if err != nil {
		t.Fatalf("CreateDesc(owning): %v", err)
	}
	t.Cleanup(func() { _ = Remove(res.JID) })
	if _, err := Lookup("gojail_own"); err != nil {
		t.Fatalf("jail should exist while owned: %v", err)
	}
	if err := res.Desc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup("gojail_own"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("closing an owning descriptor must remove the jail; Lookup = %v", err)
	}
}

func TestAtDesc(t *testing.T) {
	needRoot(t)
	needDescriptors(t)

	parent, err := CreateDesc(Params{
		"name": "gojail_parent", "path": t.TempDir(), "children.max": 2,
	}, false)
	if err != nil {
		t.Fatalf("CreateDesc(parent): %v", err)
	}
	t.Cleanup(func() { _ = Remove(parent.JID) })
	defer parent.Desc.Close()

	// Create a child under the parent through its descriptor.
	child, err := Set(FlagCreate|FlagAtDesc, Params{
		"desc": parent.Desc, "name": "child", "path": t.TempDir(), "persist": true,
	})
	if err != nil {
		t.Fatalf("Set(FlagAtDesc): %v", err)
	}
	p, err := Get(child.JID, "name", "parent")
	if err != nil || p["parent"] != parent.JID {
		t.Errorf("child = %v, %v; want parent %d", p, err, parent.JID)
	}
	t.Logf("child: %v", p)
}

// --- runtime type discovery ---

// These assert the sysctl resolver path, not the static fallback: a
// parameter missing from the static table must still get a real type.
func TestDiscoveryUsesKernel(t *testing.T) {
	if resolver == nil {
		t.Fatal("resolver not installed on FreeBSD")
	}
	for name, want := range map[string]struct {
		typ   string
		array bool
	}{
		"name":          {"string", false},
		"host.hostname": {"string", false},
		"path":          {"string", false},
		"securelevel":   {"int", false},
		"allow.chflags": {"bool", false},
		"persist":       {"bool", false},
		"ip4.addr":      {"ipv4", true},
		"ip6.addr":      {"ipv6", true},
		"vnet":          {"jailsys", false}, // a node, resolved via its empty-named child
		"ip4":           {"jailsys", false},
	} {
		pi, err := DescribeParam(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		t.Logf("%s: %+v", name, pi)
		if pi.Type != want.typ || pi.Array != want.array {
			t.Errorf("%s = %+v, want %s array=%v", name, pi, want.typ, want.array)
		}
	}
	if pi, _ := DescribeParam("host.hostname"); pi.Size <= 0 {
		t.Errorf("string size not discovered: %+v", pi)
	}
	if pi, _ := DescribeParam("securelevel"); pi.Size != 4 {
		t.Errorf("securelevel size = %d", pi.Size)
	}
	if pi, _ := DescribeParam("host.hostid"); pi.Size != longSize || pi.Type != "uint" {
		t.Errorf("host.hostid = %+v", pi)
	}
}

func TestListParams(t *testing.T) {
	infos, err := ListParams()
	if err != nil {
		t.Fatalf("ListParams: %v", err)
	}
	have := map[string]ParamInfo{}
	for _, pi := range infos {
		have[pi.Name] = pi
		if pi.Type == "node" || pi.Name == "" || pi.Name[len(pi.Name)-1] == '.' {
			t.Errorf("structural entry leaked into the list: %+v", pi)
		}
	}
	t.Logf("%d parameters", len(infos))
	for _, n := range []string{"jid", "name", "path", "host.hostname", "ip4.addr", "ip6.addr", "allow.chflags", "persist", "securelevel", "vnet", "parent"} {
		if _, ok := have[n]; !ok {
			t.Errorf("%s missing from ListParams", n)
		}
	}
	if _, ok := have["allow"]; ok {
		t.Error("the group node \"allow\" must not be listed")
	}
	for _, pi := range infos {
		if pi.Type == "unsupported" {
			t.Logf("unsupported: %+v", pi)
		}
	}
}

func TestUnknownParameterFailsBeforeSyscall(t *testing.T) {
	needRoot(t)
	_, err := Create(Params{"name": "gojail_bogus", "path": "/", "bogus.x": "1"})
	var pe *ParamError
	if !errors.As(err, &pe) || !errors.Is(err, ErrUnknownParam) {
		t.Fatalf("err = %v, want ErrUnknownParam", err)
	}
	if _, err := Lookup("gojail_bogus"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no jail may have been created: %v", err)
	}
	if _, err := Get(1, "bogus.x"); !errors.Is(err, ErrUnknownParam) {
		t.Errorf("Get: %v", err)
	}
}

func TestGetAll(t *testing.T) {
	needRoot(t)
	jid := create(t, "gojail_all", t.TempDir(), Params{
		"host.hostname": "all.test",
		"ip4.addr":      []netip.Addr{netip.MustParseAddr("127.0.1.2")},
	})
	p, err := GetAll(jid)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	t.Logf("%d parameters", len(p))
	if p["jid"] != jid || p["name"] != "gojail_all" || p["host.hostname"] != "all.test" {
		t.Errorf("unexpected: jid=%v name=%v hostname=%v", p["jid"], p["name"], p["host.hostname"])
	}
	if ips, _ := p["ip4.addr"].([]netip.Addr); len(ips) != 1 {
		t.Errorf("ip4.addr = %v", p["ip4.addr"])
	}
	if len(p) < 20 {
		t.Errorf("suspiciously few parameters: %d", len(p))
	}
}

// The sizing/fetch race: the address list changes length while another
// goroutine reads it. libjail's slop-and-retry must hide that.
func TestArrayRace(t *testing.T) {
	needRoot(t)
	one := []netip.Addr{netip.MustParseAddr("127.0.2.1")}
	many := []netip.Addr{
		netip.MustParseAddr("127.0.2.1"), netip.MustParseAddr("127.0.2.2"),
		netip.MustParseAddr("127.0.2.3"), netip.MustParseAddr("127.0.2.4"),
	}
	jid := create(t, "gojail_race", t.TempDir(), Params{"ip4.addr": one})

	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			addrs := one
			if i%2 == 1 {
				addrs = many
			}
			if err := Update(Params{"jid": jid, "ip4.addr": addrs}); err != nil {
				done <- err
				return
			}
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	reads := 0
	for time.Now().Before(deadline) {
		p, err := Get(jid, "ip4.addr")
		if err != nil {
			close(stop)
			t.Fatalf("Get after %d reads: %v", reads, err)
		}
		if n := len(p["ip4.addr"].([]netip.Addr)); n != 1 && n != 4 {
			close(stop)
			t.Fatalf("torn read: %d addresses", n)
		}
		reads++
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatalf("Update: %v", err)
	}
	t.Logf("%d reads without error", reads)
}

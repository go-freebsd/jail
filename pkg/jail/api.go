package jail

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"syscall"
)

// Flags select the behavior of Set and GetWith. They are the JAIL_* flags
// of jail_set(2) and jail_get(2) from <sys/jail.h>.
//
// jail_get accepts only FlagDying and the four descriptor flags; the
// kernel rejects the rest with EINVAL. The descriptor flags need FreeBSD 15.
type Flags int

const (
	FlagCreate  Flags = 0x01 // create the jail if it does not exist
	FlagUpdate  Flags = 0x02 // update an existing jail
	FlagAttach  Flags = 0x04 // attach the calling process on creation
	FlagDying   Flags = 0x08 // also match jails that are being removed
	FlagUseDesc Flags = 0x10 // "desc" identifies the jail (instead of jid/name)
	FlagAtDesc  Flags = 0x20 // "desc" is the parent context for the lookup/creation
	FlagGetDesc Flags = 0x40 // return a new descriptor for the jail
	FlagOwnDesc Flags = 0x80 // return a new owning descriptor: closing it removes the jail
)

// Info is a summary of a jail, as returned by List.
type Info struct {
	JID      int
	Parent   int
	Name     string
	Path     string
	Hostname string
	Persist  bool
	Dying    bool
	IP4      []netip.Addr
	IP6      []netip.Addr
}

var infoNames = []string{
	"jid", "parent", "name", "path", "host.hostname", "persist", "dying", "ip4.addr", "ip6.addr",
}

// Result is the outcome of Set.
type Result struct {
	JID int
	// Desc is set when the call used FlagGetDesc or FlagOwnDesc. The caller
	// must Close it.
	Desc *Desc
}

// Set is the general jail_set(2) call. p holds the parameters, including
// the jail selector ("jid" or "name", or "desc" with FlagUseDesc/FlagAtDesc).
// With FlagGetDesc or FlagOwnDesc the "desc" parameter is an output and must
// not be in p.
//
// Create, CreateDesc, CreateAttach and Update cover the common cases.
func Set(flags Flags, p Params) (Result, error) {
	entries, err := encode(p)
	if err != nil {
		return Result{JID: -1}, err
	}
	wantDesc := flags&(FlagGetDesc|FlagOwnDesc) != 0
	if wantDesc {
		if _, ok := p["desc"]; ok {
			return Result{JID: -1}, errors.New(`jail: "desc" is an output with FlagGetDesc/FlagOwnDesc`)
		}
		entries = append(entries, entry{name: "desc", val: make([]byte, 4)})
	}
	jid, err := sysSet(entries, int(flags))
	if err != nil {
		return Result{JID: -1}, err
	}
	r := Result{JID: jid}
	if wantDesc {
		fd := binary.NativeEndian.Uint32(entries[len(entries)-1].val)
		r.Desc = &Desc{fd: int(int32(fd))}
	}
	return r, nil
}

func withPersist(p Params) Params {
	q := make(Params, len(p)+1)
	for k, v := range p {
		q[k] = v
	}
	if _, ok := q["persist"]; !ok {
		q["persist"] = true
	}
	return q
}

// Create creates a new jail and returns its jid. The jail is made
// persistent unless p says otherwise; a non-persistent jail without
// processes is removed by the kernel right away.
//
// At minimum p usually holds "name" and "path".
func Create(p Params) (int, error) {
	r, err := Set(FlagCreate, withPersist(p))
	return r.JID, err
}

// CreateDesc is Create that also returns a jail descriptor (FreeBSD 15+).
// With owning set, closing the descriptor removes the jail.
func CreateDesc(p Params, owning bool) (Result, error) {
	f := FlagCreate | FlagGetDesc
	if owning {
		f = FlagCreate | FlagOwnDesc
	}
	return Set(f, withPersist(p))
}

// CreateAttach creates a jail and moves the calling process into it,
// irreversibly (jail_set with JAIL_CREATE|JAIL_ATTACH). The jail is not
// forced to be persistent.
func CreateAttach(p Params) (int, error) {
	r, err := Set(FlagCreate|FlagAttach, p)
	return r.JID, err
}

// Update modifies an existing jail. p must identify it with "jid" or "name".
func Update(p Params) error {
	if _, ok := p["jid"]; !ok {
		if _, ok := p["name"]; !ok {
			return errors.New(`jail: Update needs "jid" or "name"`)
		}
	}
	_, err := Set(FlagUpdate, p)
	return err
}

// Attach moves the whole calling process into the jail, irreversibly
// (jail_attach(2)). To run something in a jail from a long-lived Go program
// use Command.
func Attach(jid int) error { return sysAttach(jid) }

// Remove removes the jail and kills every process in it (jail_remove(2)).
func Remove(jid int) error { return sysRemove(jid) }

// LegacySpec describes a jail for the deprecated jail(2) call.
type LegacySpec struct {
	Path     string // required: jail root
	Hostname string
	Name     string // optional jail name
	IP4      []netip.Addr
	IP6      []netip.Addr
}

// LegacyJail is the deprecated jail(2) system call (struct jail version 2).
// It creates the jail and locks the calling process into it irreversibly,
// like CreateAttach. Prefer Create plus Command, or CreateAttach.
func LegacyJail(s LegacySpec) (int, error) {
	if s.Path == "" {
		return -1, errors.New("jail: LegacySpec.Path is required")
	}
	ip4, ok4 := packAddrs(s.IP4, true)
	ip6, ok6 := packAddrs(s.IP6, false)
	if !ok4 || !ok6 {
		return -1, errors.New("jail: LegacySpec has an invalid or wrong-family address")
	}
	return sysLegacyJail(s.Path, s.Hostname, s.Name, ip4, ip6)
}

// Desc is a jail descriptor (FreeBSD 15+): a file descriptor that refers to
// one jail and, unlike a jid, cannot be recycled for another jail.
// Close it when done; for an owning descriptor Close removes the jail.
type Desc struct{ fd int }

// OpenDesc returns a new descriptor for jail jid; with owning set, closing
// it removes the jail.
func OpenDesc(jid int, owning bool) (*Desc, error) {
	f := FlagGetDesc
	if owning {
		f = FlagOwnDesc
	}
	_, d, err := GetWith(f, Params{"jid": jid}, "jid")
	return d, err
}

// Fd returns the underlying file descriptor.
func (d *Desc) Fd() int { return d.fd }

// Close closes the descriptor. It is safe to call more than once.
func (d *Desc) Close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	fd := d.fd
	d.fd = -1
	return sysClose(fd)
}

// Attach moves the calling process into the jail (jail_attach_jd(2)).
func (d *Desc) Attach() error { return sysAttachJD(d.fd) }

// Remove removes the jail (jail_remove_jd(2)).
func (d *Desc) Remove() error { return sysRemoveJD(d.fd) }

// Get reads parameters of the jail; see Get for the defaults.
func (d *Desc) Get(names ...string) (Params, error) {
	p, _, err := GetWith(FlagUseDesc, Params{"desc": d}, names...)
	return p, err
}

// Update modifies the jail.
func (d *Desc) Update(p Params) error {
	q := make(Params, len(p)+1)
	for k, v := range p {
		q[k] = v
	}
	q["desc"] = d
	_, err := Set(FlagUpdate|FlagUseDesc, q)
	return err
}

// Lookup returns the jid of the jail with the given name.
func Lookup(name string) (int, error) {
	p, _, err := GetWith(0, Params{"name": name}, "jid")
	if err != nil {
		return -1, err
	}
	return p["jid"].(int), nil
}

// Get returns the named parameters of jail jid. With no names it returns
// jid, parent, name, path, host.hostname, persist, dying, ip4.addr and ip6.addr.
func Get(jid int, names ...string) (Params, error) {
	p, _, err := GetWith(0, Params{"jid": jid}, names...)
	return p, err
}

// GetByName is Get for a jail identified by name.
func GetByName(name string, names ...string) (Params, error) {
	p, _, err := GetWith(0, Params{"name": name}, names...)
	return p, err
}

// GetWith is the general jail_get(2) call. sel holds the selector ("jid",
// "name", "lastjid", or "desc" with FlagUseDesc/FlagAtDesc). With FlagGetDesc
// or FlagOwnDesc it also returns a new descriptor, which the caller must Close.
func GetWith(flags Flags, sel Params, names ...string) (Params, *Desc, error) {
	lookup, err := encode(sel)
	if err != nil {
		return nil, nil, err
	}
	p, _, d, err := query(flags, lookup, names)
	return p, d, err
}

// Array handling, as in libjail: leave room for elements added between
// sizing a list and fetching it, and retry if the list still outgrew it.
const (
	arraySlop   = 5
	arraySanity = 5
)

type getFunc func(entries []entry, flags int) (int, error)

// getWithRetry runs get over entries, whose first nl items are the lookup.
// Variable-length (probe) entries are sized with a throwaway call first,
// then fetched with arraySlop extra elements; if the kernel answers EINVAL
// without a message (the list grew again), the sizing is repeated, up to
// arraySanity times.
func getWithRetry(get getFunc, nl int, entries []entry, flags Flags) (int, error) {
	var arrays []int
	for i, e := range entries {
		if e.probe {
			arrays = append(arrays, i)
		}
	}
	if len(arrays) == 0 {
		return get(entries, int(flags))
	}
	// Never create a descriptor in the sizing call.
	probeFlags := int(flags &^ (FlagGetDesc | FlagOwnDesc))
	for try := 0; ; try++ {
		probes := append([]entry(nil), entries[:nl]...)
		for _, i := range arrays {
			probes = append(probes, entry{name: entries[i].name, probe: true})
		}
		if _, err := get(probes, probeFlags); err != nil {
			return -1, err
		}
		for j, i := range arrays {
			n := len(probes[nl+j].val)
			entries[i].probe = false
			entries[i].val = make([]byte, n+arraySlop*entries[i].elem)
		}
		jid, err := get(entries, int(flags))
		var je *Error
		if err != nil && try < arraySanity && errors.Is(err, syscall.EINVAL) &&
			errors.As(err, &je) && je.Msg == "" {
			continue
		}
		return jid, err
	}
}

// query runs jail_get with lookup as the selector and returns the requested
// parameters plus the jid found.
func query(flags Flags, lookup []entry, names []string) (Params, int, *Desc, error) {
	if len(names) == 0 {
		names = infoNames
	}
	wantDesc := flags&(FlagGetDesc|FlagOwnDesc) != 0
	nl := len(lookup)
	entries := append([]entry(nil), lookup...)
	for _, n := range names {
		e, err := readEntry(n)
		if err != nil {
			return nil, -1, nil, err
		}
		entries = append(entries, e)
	}
	end := len(entries)
	if wantDesc {
		entries = append(entries, entry{name: "desc", val: make([]byte, 4)})
	}
	jid, err := getWithRetry(sysGet, nl, entries, flags)
	if err != nil {
		return nil, -1, nil, err
	}
	var desc *Desc
	if wantDesc {
		fd := binary.NativeEndian.Uint32(entries[end].val)
		desc = &Desc{fd: int(int32(fd))}
	}
	out := make(Params, len(names))
	for _, e := range entries[nl:end] {
		v, err := decode(e.name, e.val)
		if err != nil {
			desc.Close()
			return nil, -1, nil, err
		}
		out[e.name] = v
	}
	return out, jid, desc, nil
}

// ListParams returns every parameter the kernel defines, with its type
// (libjail's jailparam_all). Structural groups such as "allow" are omitted.
// It needs FreeBSD.
func ListParams() ([]ParamInfo, error) {
	names, err := listParamNames()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(names))
	var out []ParamInfo
	for _, n := range names {
		// A node described by an empty-named child is listed as "name.".
		n = strings.TrimSuffix(n, ".")
		if seen[n] {
			continue
		}
		seen[n] = true
		t, err := typeOf(n)
		if err != nil {
			return nil, err
		}
		if t.class == clNode {
			continue
		}
		out = append(out, t.info(n))
	}
	return out, nil
}

// DescribeParam returns the kernel's definition of one parameter, or a
// *ParamError wrapping ErrUnknownParam. Off FreeBSD it reflects only the
// built-in table.
func DescribeParam(name string) (ParamInfo, error) {
	t, err := typeOf(name)
	if err != nil {
		return ParamInfo{}, err
	}
	return t.info(name), nil
}

// GetAll returns every readable parameter of jail jid, like `jls -v`.
func GetAll(jid int) (Params, error) { return getAll(0, Params{"jid": jid}) }

// GetAll returns every readable parameter of the jail.
func (d *Desc) GetAll() (Params, error) { return getAll(FlagUseDesc, Params{"desc": d}) }

func getAll(flags Flags, sel Params) (Params, error) {
	infos, err := ListParams()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, pi := range infos {
		if pi.Name == "lastjid" || pi.Name == "desc" || pi.Type == "unsupported" {
			continue
		}
		names = append(names, pi.Name)
	}
	p, _, err := GetWith(flags, sel, names...)
	return p, err
}

// List returns all running (non-dying) jails visible to the caller.
func List() ([]Info, error) { return list(0) }

// ListDying is List including jails that are being removed.
func ListDying() ([]Info, error) { return list(FlagDying) }

func list(flags Flags) ([]Info, error) {
	var infos []Info
	for last := 0; ; {
		lk, err := encode(Params{"lastjid": last})
		if err != nil {
			return nil, err
		}
		p, jid, _, err := query(flags, lk, nil)
		if errors.Is(err, syscall.ENOENT) {
			return infos, nil
		}
		if err != nil {
			return nil, err
		}
		infos = append(infos, infoFrom(p))
		last = jid
	}
}

func infoFrom(p Params) Info {
	i := Info{}
	i.JID, _ = p["jid"].(int)
	i.Parent, _ = p["parent"].(int)
	i.Name, _ = p["name"].(string)
	i.Path, _ = p["path"].(string)
	i.Hostname, _ = p["host.hostname"].(string)
	i.Persist, _ = p["persist"].(bool)
	i.Dying, _ = p["dying"].(bool)
	i.IP4, _ = p["ip4.addr"].([]netip.Addr)
	i.IP6, _ = p["ip6.addr"].([]netip.Addr)
	return i
}

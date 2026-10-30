# jail

Pure-Go (no cgo, no `-ljail`) access to FreeBSD jails via `jail_set(2)`,
`jail_get(2)`, `jail_attach(2)` and `jail_remove(2)`. Builds on any OS;
operations return `jail.ErrUnsupported` off FreeBSD.

```go
import "github.com/go-freebsd/jail/pkg/jail"

jid, err := jail.Create(jail.Params{
	"name":          "web",
	"path":          "/jails/web",
	"host.hostname": "web.example.org",
	"ip4.addr":      netip.MustParseAddr("192.0.2.10"),
	"allow.raw_sockets": true,
})

info, _ := jail.List()
p, _ := jail.GetByName("web", "host.hostname", "securelevel")

out, err := jail.Command(jid, "/bin/sh", "-c", "hostname").Output()

jail.Update(jail.Params{"name": "web", "host.hostname": "new.example.org"})
jail.Remove(jid)
```

Errors are `*jail.Error` carrying the kernel's `errmsg` text.

## Parameter types

Like libjail, parameter types come from the kernel at runtime
(`security.jail.param.*` via sysctl), so parameters added by newer releases or
modules work without library changes. A small built-in table is the fallback
when the kernel cannot be asked, and the only source off FreeBSD.

```go
jail.ListParams()               // every parameter with its type (like jls -v)
jail.DescribeParam("ip4.addr")  // {Type: "ipv4", Array: true, ...}
jail.GetAll(jid)                // every readable parameter of a jail
```

Unknown names fail early with `*jail.ParamError` (`errors.Is(err,
jail.ErrUnknownParam)`) before any syscall. Address lists are fetched with
spare room and retried if they change while being read, as libjail does.
`S,mac` and other struct types are not supported yet.

## Syscall coverage

All seven jail syscalls in FreeBSD's `syscalls.master`:

| Syscall | API |
|---|---|
| `jail_set(2)` | `Set` (all flags), `Create`, `CreateDesc`, `CreateAttach`, `Update`, `Desc.Update` |
| `jail_get(2)` | `GetWith` (all flags), `Get`, `GetByName`, `Lookup`, `List`, `ListDying`, `Desc.Get` |
| `jail_attach(2)` | `Attach` |
| `jail_remove(2)` | `Remove` |
| `jail(2)` (legacy, deprecated) | `LegacyJail` |
| `jail_attach_jd(2)` (FreeBSD 15) | `Desc.Attach` |
| `jail_remove_jd(2)` (FreeBSD 15) | `Desc.Remove` |

Jail descriptors (`FlagUseDesc`, `FlagAtDesc`, `FlagGetDesc`, `FlagOwnDesc`)
need FreeBSD 15; older kernels answer `EINVAL`/`ENOSYS`.

`Attach`, `CreateAttach`, `LegacyJail` and `Desc.Attach` confine the whole
calling process irreversibly. In a long-lived program use `Command`.

## Testing

`go test ./...` covers parameter encoding anywhere. The jail lifecycle tests
run as root on FreeBSD; CI runs them in a FreeBSD VM (`vmactions/freebsd-vm`).

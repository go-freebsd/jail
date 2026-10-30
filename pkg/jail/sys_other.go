//go:build !freebsd

package jail

func sysSet(entries []entry, flags int) (int, error) { return -1, ErrUnsupported }
func sysGet(entries []entry, flags int) (int, error) { return -1, ErrUnsupported }
func sysAttach(jid int) error                        { return ErrUnsupported }
func sysRemove(jid int) error                        { return ErrUnsupported }
func sysAttachJD(fd int) error                       { return ErrUnsupported }
func sysRemoveJD(fd int) error                       { return ErrUnsupported }
func sysClose(fd int) error                          { return ErrUnsupported }

func sysLegacyJail(path, hostname, name string, ip4, ip6 []byte) (int, error) {
	return -1, ErrUnsupported
}

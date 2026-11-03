//go:build freebsd && cgo

package jail

import (
	"strings"
	"testing"
)

// TestResolverParity checks that libjail (jailparam_init) and the sysctl walk
// agree on the type of every parameter the kernel defines. The two backends
// must be interchangeable.
func TestResolverParity(t *testing.T) {
	names, err := listParamNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no jail parameters found")
	}
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		if seen[n] {
			continue
		}
		seen[n] = true

		sc, sf, sn, serr := resolveFromSysctl(n)
		lc, lf, ln, lerr := resolveFromLibjail(n)
		if (serr == nil) != (lerr == nil) {
			t.Errorf("%s: sysctl err=%v, libjail err=%v", n, serr, lerr)
			continue
		}
		if serr != nil {
			continue
		}
		st, lt := parseType(sc, sf, sn), parseType(lc, lf, ln)
		// The raw format string is only known to the sysctl backend.
		st.format, lt.format = "", ""
		// A group node is described by its empty child in both backends; a
		// node left unresolved by one of them is not a parameter.
		if st != lt {
			t.Errorf("%s: sysctl %+v (ctl %#x fmt %q len %d) != libjail %+v (ctl %#x fmt %q len %d)",
				n, st, sc, sf, sn, lt, lc, lf, ln)
		}
	}
}

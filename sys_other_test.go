//go:build !freebsd

package jail

import (
	"errors"
	"testing"
)

func TestUnsupported(t *testing.T) {
	d := &Desc{fd: 3}
	for name, err := range map[string]error{
		"Attach":      Attach(1),
		"Remove":      Remove(1),
		"Desc.Attach": d.Attach(),
		"Desc.Remove": d.Remove(),
		"Command":     Command(1, "/bin/sh").Run(),
		"Create":      func() error { _, err := Create(Params{"name": "x"}); return err }(),
		"List":        func() error { _, err := List(); return err }(),
		"LegacyJail":  func() error { _, err := LegacyJail(LegacySpec{Path: "/"}); return err }(),
	} {
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v, want ErrUnsupported", name, err)
		}
	}
}

func TestListParamsUnsupported(t *testing.T) {
	if _, err := ListParams(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ListParams: %v, want ErrUnsupported", err)
	}
}

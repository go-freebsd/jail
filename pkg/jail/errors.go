package jail

import (
	"errors"
	"fmt"
	"syscall"
)

// ErrUnsupported is returned by every operation on platforms other than
// FreeBSD.
var ErrUnsupported = errors.New("jail: only supported on FreeBSD")

// ErrUnknownParam is wrapped by *ParamError when the kernel has no such
// jail parameter. It deliberately does not match syscall.ENOENT.
var ErrUnknownParam = errors.New("unknown parameter")

// ParamError reports a problem with a named parameter, before any system
// call is made.
type ParamError struct {
	Name string
	Err  error
}

func (e *ParamError) Error() string { return fmt.Sprintf("%v: %s", e.Err, e.Name) }
func (e *ParamError) Unwrap() error { return e.Err }

// Error is a failed jail system call. Msg carries the kernel's "errmsg"
// text when it provided one (for example "path is not a directory").
//
// It unwraps to the syscall.Errno, so errors.Is(err, fs.ErrNotExist) and
// errors.Is(err, syscall.EPERM) work as usual.
type Error struct {
	Op    string
	Errno syscall.Errno
	Msg   string
}

func (e *Error) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("%s: %v: %s", e.Op, e.Errno, e.Msg)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Errno)
}

func (e *Error) Unwrap() error { return e.Errno }

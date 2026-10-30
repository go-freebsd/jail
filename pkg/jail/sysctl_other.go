//go:build !freebsd

package jail

func listParamNames() ([]string, error) { return nil, ErrUnsupported }

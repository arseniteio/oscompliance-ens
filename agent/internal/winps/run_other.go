//go:build !windows

package winps

func Run(string) ([]byte, error) {
	return nil, ErrUnsupported
}

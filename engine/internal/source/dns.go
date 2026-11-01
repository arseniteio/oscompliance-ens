package source

import (
	"context"
	"errors"
	"net"
	"time"
)

// TXT reads the TXT records of a name; a name without them is not an error.
func (s *Source) TXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	records, err := net.DefaultResolver.LookupTXT(ctx, name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nil, nil
	}
	return records, err
}

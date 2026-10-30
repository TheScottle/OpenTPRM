package egress

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// Client is the only outbound network path (SEC-NET / design principle).
type Client struct {
	mu      sync.RWMutex
	mode    string // none | allowlist
	allow   map[string]bool // host:port
}

func New(mode string, allow []string) *Client {
	c := &Client{mode: mode, allow: map[string]bool{}}
	for _, a := range allow {
		c.allow[strings.ToLower(a)] = true
	}
	return c
}

// Dial checks the allow-list before connecting (AT-12).
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.mode == "none" {
		return nil, fmt.Errorf("egress denied: mode=none")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(host + ":" + port)
	if !c.allow[key] {
		return nil, fmt.Errorf("egress denied: %s not allowlisted", key)
	}
	return net.Dial(network, addr)
}

// Allowed reports whether host:port is permittted.
func (c *Client) Allowed(hostPort string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.mode == "none" {
		return false
	}
	return c.allow[strings.ToLower(hostPort)]
}

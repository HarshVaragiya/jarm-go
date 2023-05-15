package jarm

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

var DefualtBackoff = func(r, m int) time.Duration {
	return time.Second
}

type Target struct {
	Host    string
	Port    int
	Retries int
	Backoff func(r, m int) time.Duration
}

type Result struct {
	Target Target
	Hash   string
	Error  error
}

func Fingerprint(t Target) (*Result, error) {
	results := []string{}
	for _, probe := range GetProbes(t.Host, t.Port) {
		dialer := proxy.FromEnvironmentUsing(&net.Dialer{Timeout: time.Second * 2})
		addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))

		c := net.Conn(nil)
		n := 0

		for c == nil && n <= t.Retries {
			// Ignoring error since error message was already being dropped.
			// Also, if theres an error, c == nil.
			if c, _ = dialer.Dial("tcp", addr); c != nil || t.Retries == 0 {
				break
			}

			bo := t.Backoff
			if bo == nil {
				bo = DefualtBackoff
			}

			time.Sleep(bo(n, t.Retries))

			n++
		}

		if c == nil {
			return nil, fmt.Errorf("error building JARM fingerprint")
		}

		data := BuildProbe(probe)
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, err := c.Write(data)
		if err != nil {
			results = append(results, "")
			c.Close()
			continue
		}

		c.SetReadDeadline(time.Now().Add(time.Second * 5))
		buff := make([]byte, 1484)
		c.Read(buff)
		c.Close()

		ans, err := ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}

		results = append(results, ans)
	}

	return &Result{
		Target: t,
		Hash:   RawHashToFuzzyHash(strings.Join(results, ",")),
	}, nil
}

// Fingerprint probes a single host/port
func AsyncFingerprint(t Target, och chan *Result) {
	r, err := Fingerprint(t)
	if err != nil || r == nil {
		och <- &Result{
			Target: t,
			Error:  err,
		}
	} else {
		och <- r
	}
}

package authn_test

import (
	"net/http"
	"os"
)

func writeRestricted(path, body string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o400)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(body)
	return err
}

type httpRequest struct {
	method, sfs, origin string
}

func (r *httpRequest) asHTTP() *http.Request {
	req, _ := http.NewRequest(r.method, "https://app.local/api/v1/vendors", nil)
	if r.sfs != "" {
		req.Header.Set("Sec-Fetch-Site", r.sfs)
	}
	if r.origin != "" {
		req.Header.Set("Origin", r.origin)
	}
	return req
}

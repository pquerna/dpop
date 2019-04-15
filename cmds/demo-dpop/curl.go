package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func req2curl(req *http.Request) (string, error) {
	var b []byte
	var err error
	buf := &strings.Builder{}

	_, err = fmt.Fprintf(buf, "curl -X %s '%s'", req.Method, req.URL.String())
	if err != nil {
		return "", err
	}

	for k, v := range req.Header {
		_, err = fmt.Fprintf(buf, " -H '%s: %s'", k, strings.Join(v, ", "))
		if err != nil {
			return "", err
		}
	}

	if req.Body != nil {
		b, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		_, err = fmt.Fprintf(buf, " -d %q", string(b))
		if err != nil {
			return "", err
		}
	}

	// reset body
	body := bytes.NewBuffer(b)
	req.Body = ioutil.NopCloser(body)

	return buf.String(), nil
}

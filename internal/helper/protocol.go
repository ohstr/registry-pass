package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// maxInput bounds what the helper reads from stdin.
const maxInput = 64 << 10

// Run executes one credential-helper action (get, store, erase, list,
// version) per the docker-credential-helpers protocol and returns the
// exit code.
func (h *Helper) Run(ctx context.Context, action string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	in := io.LimitReader(stdin, maxInput)
	switch action {
	case "get":
		server, err := readLine(in)
		if err != nil {
			fmt.Fprintln(stdout, err)
			return 1
		}
		creds, err := h.Get(ctx, server)
		if err != nil {
			// The protocol reports errors on stdout; Docker matches the
			// not-found message to fall back to anonymous access.
			fmt.Fprintln(stdout, err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(creds); err != nil {
			return 1
		}
		return 0
	case "store", "erase":
		// Credentials are signed on demand, so docker login/logout have
		// nothing to keep or remove.
		_, _ = io.Copy(io.Discard, in)
		return 0
	case "list":
		_, _ = fmt.Fprintln(stdout, "{}")
		return 0
	case "version":
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	}
	fmt.Fprintf(stderr, "usage: docker-credential-registry-pass <get|store|erase|list|version>\n")
	return 2
}

func readLine(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), maxInput)
	if !sc.Scan() {
		return "", fmt.Errorf("no server URL on stdin")
	}
	s := strings.TrimSpace(sc.Text())
	if s == "" {
		return "", fmt.Errorf("no server URL on stdin")
	}
	return s, nil
}

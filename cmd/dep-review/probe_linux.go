//go:build sandboxtest && linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
)

// runProbe: dep-review probe --proxy IP:PORT --model M [--deny-tcp HOST:PORT]... [--deny-dns NAME]...
//
// The isolation probes, run inside the reviewer sandbox by CI's sandbox job
// (`dep-review review --test-probe`), with exactly the container flags,
// network and proxy of a real review; only the command differs. It is
// this static binary, bind-mounted read-only, because the reviewer image
// has no shell and no interpreter. Exit status 0 means every probe passed.
func runProbe(args []string) error {
	fs := newFlagSet("probe")
	proxy := fs.String("proxy", "", "the proxy's address")
	model := fs.String("model", "", "the gate's model")
	var denyTCP, denyDNS, denyHTTP, readonly stringList
	fs.Var(&denyTCP, "deny-tcp", "HOST:PORT that must be unreachable")
	fs.Var(&denyDNS, "deny-dns", "name that must not resolve")
	fs.Var(&denyHTTP, "deny-http", "URL that must not answer")
	fs.Var(&readonly, "readonly", "directory that must not be writable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := &prober{}

	// Identity and kernel.
	p.check(os.Getuid() != 0 && os.Getgid() != 0, "non-root (uid=%d gid=%d)", os.Getuid(), os.Getgid())
	status, _ := os.ReadFile("/proc/self/status")
	p.check(field(status, "CapEff") != "" && strings.Trim(field(status, "CapEff"), "0") == "", "no effective capabilities (%s)", field(status, "CapEff"))
	p.check(field(status, "NoNewPrivs") == "1", "no_new_privs set")
	// gVisor's kernel log (syslog(2), what dmesg reads) starts with its own
	// boot banner; its /proc/version names a "-gvisor" kernel. Under runc
	// the first needs CAP_SYSLOG and the second is the host kernel.
	buf := make([]byte, 1<<16)
	n, err := syscall.Klogctl(3, buf) // SYSLOG_ACTION_READ_ALL
	klog := string(buf[:max(n, 0)])
	ver, _ := os.ReadFile("/proc/version")
	fmt.Printf("  /proc/version: %s\n", strings.TrimSpace(string(ver)))
	p.check(strings.Contains(klog, "gVisor") || strings.Contains(string(ver), "-gvisor"), "kernel is gVisor (syslog err %v, gVisor in log: %v)", err, strings.Contains(klog, "gVisor"))

	// Environment.
	var names, bad []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		names = append(names, k)
		up := strings.ToUpper(k)
		if strings.HasPrefix(up, "GITHUB_") || strings.HasPrefix(up, "ACTIONS_") || strings.HasPrefix(up, "RUNNER_") {
			bad = append(bad, k)
		}
		for _, w := range []string{"TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "KEY"} {
			if strings.Contains(up, w) && k != "ANTHROPIC_API_KEY" {
				bad = append(bad, k)
			}
		}
	}
	sort.Strings(names)
	fmt.Printf("  env: %s\n", strings.Join(names, " "))
	p.check(len(bad) == 0, "no credential-looking or runner variables (%s)", strings.Join(bad, " "))
	p.check(os.Getenv("ANTHROPIC_API_KEY") == "dep-review-sandbox-no-credential", "ANTHROPIC_API_KEY is the placeholder")

	// Filesystem: no shell or interpreter, read-only everywhere but tmpfs.
	for _, b := range []string{"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/local/bin/node", "/usr/bin/node", "/usr/bin/apt", "/usr/bin/dpkg", "/usr/local/bin/npm"} {
		_, err := os.Lstat(b)
		p.check(errors.Is(err, os.ErrNotExist), "absent: %s", b)
	}
	for _, d := range append([]string{"/", "/usr", "/etc", "/work"}, readonly...) {
		p.check(!canWrite(d), "read-only: %s", d)
	}
	home, _ := os.UserHomeDir()
	for _, d := range []string{home, "/tmp"} {
		p.check(canWrite(d), "writable tmpfs: %s", d)
	}
	mounts, _ := os.ReadFile("/proc/self/mounts")
	fmt.Printf("  mounts:\n    %s\n", strings.ReplaceAll(strings.TrimSpace(string(mounts)), "\n", "\n    "))
	rootRO := false
	for _, l := range strings.Split(string(mounts), "\n") {
		if f := strings.Fields(l); len(f) > 3 && f[1] == "/" {
			rootRO = slices.Contains(strings.Split(f[3], ","), "ro")
		}
	}
	p.check(rootRO, "root filesystem mounted ro")
	entries, _ := os.ReadDir("/work")
	var work []string
	for _, e := range entries {
		work = append(work, e.Name())
	}
	p.check(strings.Join(work, ",") == "evidence,repo", "/work holds exactly evidence and repo (%v)", work)

	// Network.
	for _, name := range denyDNS {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(ctx, name)
		cancel()
		p.check(err != nil, "no DNS: %s (%v %v)", name, addrs, err)
	}
	public := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, "8.8.8.8:53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	addrs, err := public.LookupHost(ctx, "github.com")
	cancel()
	p.check(err != nil, "no DNS via a public resolver (%v %v)", addrs, err)
	for _, t := range denyTCP {
		c, err := net.DialTimeout("tcp", t, 4*time.Second)
		if c != nil {
			c.Close()
		}
		p.check(err != nil, "no TCP: %s (%v)", t, err)
	}
	client := &http.Client{Timeout: 8 * time.Second}
	for _, u := range denyHTTP {
		resp, err := client.Get(u)
		if resp != nil {
			resp.Body.Close()
		}
		p.check(err != nil, "no HTTP(S): %s (%v)", u, err)
	}

	// The proxy.
	c, err := net.DialTimeout("tcp", *proxy, 4*time.Second)
	if c != nil {
		c.Close()
	}
	p.check(err == nil, "proxy reachable: %s (%v)", *proxy, err)
	msg := func(extra string) string {
		return `{"model":"` + *model + `","max_tokens":1,"messages":[{"role":"user","content":"x"}]` + extra + `}`
	}
	refused := []struct{ method, target, body string }{
		{"GET", "/v1/models", ""},
		{"GET", "/v1/messages", ""},
		{"POST", "/v1/messages/count_tokens", msg("")},
		{"POST", "/v1/messages/batches", msg("")},
		{"POST", "/v1/files", ""},
		{"POST", "/v1/complete", msg("")},
		{"POST", "/v1/oauth/token", `{"grant_type":"x"}`},
		{"POST", "/v1/messages?beta=true&x=1", msg("")},
		{"POST", "/v1/messages/../models", msg("")},
		{"POST", "/", msg("")},
		{"CONNECT", "api.anthropic.com:443", ""},
		{"POST", "http://example.com/v1/models", msg("")},
		{"POST", "/v1/messages", strings.Replace(msg(""), *model, "claude-haiku-4-5", 1)},
		{"POST", "/v1/messages", msg(`,"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]`)},
		{"POST", "/v1/messages", msg(`,"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"x"}]`)},
		{"POST", "/v1/messages", msg(`,"frobnicate":true`)},
		{"POST", "/v1/messages", msg(`,"tools":[],"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]`)},
		{"POST", "/v1/messages", `{"model":"` + *model + `","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.com/x.png"}}]}]}`},
		{"POST", "/v1/messages", `{"model":"` + *model + `","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_x"}}]}]}`},
	}
	for _, r := range refused {
		st, err := rawRequest(*proxy, r.method, r.target, r.body)
		p.check(st == http.StatusForbidden, "proxy refuses %s %s %.60s -> %d %v", r.method, r.target, r.body, st, err)
	}

	if p.failed > 0 {
		fmt.Printf("%d probe(s) FAILED\n", p.failed)
		os.Exit(1)
	}
	fmt.Println("all probes passed")
	return nil
}

type prober struct{ failed int }

func (p *prober) check(ok bool, format string, a ...any) {
	if ok {
		fmt.Printf("PASS "+format+"\n", a...)
		return
	}
	p.failed++
	fmt.Printf("FAIL "+format+"\n", a...)
}

func field(status []byte, name string) string {
	for _, l := range strings.Split(string(status), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && k == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func canWrite(dir string) bool {
	p := fmt.Sprintf("%s/.probe-%d", strings.TrimSuffix(dir, "/"), os.Getpid())
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		return false
	}
	os.Remove(p)
	return true
}

// rawRequest writes the request line as given, so absolute-form and
// CONNECT targets reach the proxy unchanged, and returns the status.
func rawRequest(addr, method, target, body string) (int, error) {
	c, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/json\r\nAnthropic-Version: 2023-06-01\r\nContent-Length: %d\r\n\r\n%s",
		method, target, addr, len(body), body)
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return 0, err
	}
	var proto string
	var st int
	if _, err := fmt.Sscanf(line, "%s %d", &proto, &st); err != nil {
		return 0, err
	}
	return st, nil
}

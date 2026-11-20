package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

// An apk index cache (/var/cache/apk/APKINDEX.<hash>.tar.gz) is a signed
// file: two concatenated gzip members, the first a tar holding
// .SIGN.RSA[256].<key>.rsa.pub (an RSA PKCS#1 v1.5 signature), the second
// the index itself; the signature covers the second member's compressed
// bytes. apk re-verifies it on every use. A changed index cache is build
// noise when its signature verifies with a key that both images carry
// unchanged.

var apkIndexRe = regexp.MustCompile(`^var/cache/apk/APKINDEX\.[0-9a-f]{8}\.tar\.gz$`)

const maxAPKIndex = 16 << 20

func apkKeyPaths(name string) []string {
	return []string{"etc/apk/keys/" + name, "usr/share/apk/keys/" + name}
}

// verifyAPKIndex checks b's signature with a key from keys (path ->
// PEM). It returns the key file name.
func verifyAPKIndex(b []byte, keys func(name string) ([]byte, bool)) (string, error) {
	r := bytes.NewReader(b)
	zr, err := gzip.NewReader(r) // bytes.Reader is an io.ByteReader: no read-ahead
	if err != nil {
		return "", err
	}
	zr.Multistream(false)
	var sigName string
	var sig []byte
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			break // the signature tar has no end-of-archive marker
		}
		if strings.HasPrefix(h.Name, ".SIGN.") {
			sigName = h.Name
			if sig, err = io.ReadAll(io.LimitReader(tr, 64<<10)); err != nil {
				return "", err
			}
			break
		}
	}
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return "", err
	}
	if sigName == "" {
		return "", errors.New("no signature member")
	}
	rest := b[len(b)-r.Len():]
	var h crypto.Hash
	var key string
	switch {
	case strings.HasPrefix(sigName, ".SIGN.RSA256."):
		h, key = crypto.SHA256, strings.TrimPrefix(sigName, ".SIGN.RSA256.")
	case strings.HasPrefix(sigName, ".SIGN.RSA."):
		h, key = crypto.SHA1, strings.TrimPrefix(sigName, ".SIGN.RSA.")
	default:
		return "", fmt.Errorf("unsupported signature %q", sigName)
	}
	if key != path.Base(key) {
		return "", fmt.Errorf("bad key name %q", key)
	}
	pemBytes, ok := keys(key)
	if !ok {
		return "", fmt.Errorf("key %s is not in both images unchanged", key)
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return "", fmt.Errorf("key %s: not PEM", key)
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", fmt.Errorf("key %s: %w", key, err)
	}
	rpub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("key %s: not RSA", key)
	}
	var sum []byte
	if h == crypto.SHA256 {
		s := sha256.Sum256(rest)
		sum = s[:]
	} else {
		s := sha1.Sum(rest)
		sum = s[:]
	}
	if err := rsa.VerifyPKCS1v15(rpub, h, sum, sig); err != nil {
		return "", fmt.Errorf("signature by %s: %w", key, err)
	}
	return key, nil
}

// unchangedKey returns a key's PEM if both images carry it byte-identical.
func unchangedKey(oldFS, newFS *rootfs) func(string) ([]byte, bool) {
	return func(name string) ([]byte, bool) {
		for _, p := range apkKeyPaths(name) {
			o, n := oldFS.Captured[p], newFS.Captured[p]
			oe, ne := oldFS.Files[p], newFS.Files[p]
			if o != nil && n != nil && oe != nil && ne != nil && oe.SHA256 == ne.SHA256 && bytes.Equal(o, n) {
				return n, true
			}
		}
		return nil, false
	}
}

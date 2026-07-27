package sources

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/SpenceChakabva/shhscan/internal/finding"
	"github.com/SpenceChakabva/shhscan/internal/scan"
)

// maxBlob caps how much of a single layer we buffer into memory.
const maxBlob = 512 << 20 // 512 MiB

// Docker scans a `docker save`-style image tarball. The outer tar contains layer
// tarballs plus JSON config/manifest. Each layer is itself a tar of the
// filesystem at that layer, so real credentials baked into an image (an .env
// copied in, an ~/.aws/credentials, an ENV secret in the config) live one level
// down. This walks both levels. Works for the classic docker format and the
// newer OCI blobs/sha256 layout, gzip-compressed layers included.
//
// Produce the input with:  docker save myimage:tag -o image.tar
func Docker(sc *scan.Scanner, tarPath string) ([]finding.Finding, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tr, closeOuter, err := maybeGzipTar(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	defer closeOuter()

	var out []finding.Finding
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("reading image tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 || hdr.Size > maxBlob {
			continue
		}
		blob, err := io.ReadAll(io.LimitReader(tr, maxBlob))
		if err != nil {
			continue
		}
		name := hdr.Name

		// Top-level JSON (image config / manifest) can carry ENV secrets.
		if strings.HasSuffix(name, ".json") {
			if !sc.Excluded(name) {
				out = append(out, scanText(sc, bytes.NewReader(blob), "docker", name)...)
			}
			continue
		}

		// Otherwise treat the blob as a (possibly gzipped) layer tar. If it
		// isn't a tar at all, fall back to scanning it as raw text.
		if inner, closeInner, ok := asTar(blob); ok {
			out = append(out, scanLayer(sc, inner, shortLayer(name))...)
			closeInner()
		} else {
			out = append(out, scanText(sc, bytes.NewReader(blob), "docker", name)...)
		}
	}
	return out, nil
}

// scanLayer walks one layer's inner tar and scans each text file.
func scanLayer(sc *scan.Scanner, tr *tar.Reader, layer string) []finding.Finding {
	var out []finding.Finding
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 || hdr.Size > MaxFileSize {
			continue
		}
		loc := layer + ":" + strings.TrimPrefix(hdr.Name, "./")
		if sc.Excluded(strings.TrimPrefix(hdr.Name, "./")) {
			continue
		}
		out = append(out, scanText(sc, io.LimitReader(tr, MaxFileSize), "docker", loc)...)
	}
	return out
}

// maybeGzipTar wraps r in a gzip reader if it looks gzipped, then returns a tar
// reader over it plus a cleanup func.
func maybeGzipTar(r *bufio.Reader) (*tar.Reader, func(), error) {
	magic, _ := r.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, func() {}, err
		}
		return tar.NewReader(gz), func() { gz.Close() }, nil
	}
	return tar.NewReader(r), func() {}, nil
}

// asTar decides whether blob is a tar (optionally gzipped) by trying to read its
// first header, and returns a fresh reader positioned at the start if so.
func asTar(blob []byte) (*tar.Reader, func(), bool) {
	makeReader := func() (*tar.Reader, func()) {
		if len(blob) >= 2 && blob[0] == 0x1f && blob[1] == 0x8b {
			gz, err := gzip.NewReader(bytes.NewReader(blob))
			if err != nil {
				return nil, func() {}
			}
			return tar.NewReader(gz), func() { gz.Close() }
		}
		return tar.NewReader(bytes.NewReader(blob)), func() {}
	}
	probe, closeProbe := makeReader()
	if probe == nil {
		return nil, nil, false
	}
	_, err := probe.Next()
	closeProbe()
	if err != nil {
		return nil, nil, false
	}
	tr, cl := makeReader()
	return tr, cl, true
}

// shortLayer turns "blobs/sha256/deadbeef..." or "abcdef.../layer.tar" into a
// short, readable label.
func shortLayer(name string) string {
	// Newer OCI layout: blobs/sha256/<hash>. Classic layout: <hash>/layer.tar.
	id := path.Base(path.Dir(name)) // the hash dir in the classic layout
	if id == "sha256" {             // OCI: hash is the file name itself
		id = path.Base(name)
	}
	if id == "." || id == "/" || id == "" {
		id = strings.TrimSuffix(path.Base(name), ".tar") // flat fallback
	}
	if len(id) > 12 {
		id = id[:12]
	}
	return "layer[" + id + "]"
}

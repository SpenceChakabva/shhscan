package sources

import (
	"bufio"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/SpenceChakabva/shhscan/internal/finding"
	"github.com/SpenceChakabva/shhscan/internal/scan"
)

// MaxFileSize is the largest single file scanned. Bigger files are almost always
// binaries or data dumps and blow up scan time for little gain.
const MaxFileSize = 5 << 20 // 5 MiB

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".terraform": true, "dist": true, "build": true,
}

// FS walks a directory tree and scans every text file line by line.
func FS(sc *scan.Scanner, root string) ([]finding.Finding, error) {
	var out []finding.Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, don't abort the whole scan
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > MaxFileSize {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel) // forward slashes on every OS: consistent
		// locations and exclude-glob matching on Windows too
		if sc.Excluded(rel) {
			return nil
		}
		out = append(out, scanText(sc, f, "fs", rel)...)
		return nil
	})
	return out, err
}

// scanText scans an arbitrary reader line by line. It first sniffs for binary
// content (a NUL byte in the first chunk) and bails on binaries. Shared by the
// fs and docker sources.
func scanText(sc *scan.Scanner, r io.Reader, source, location string) []finding.Finding {
	br := bufio.NewReader(r)
	head, _ := br.Peek(512)
	if bytes.IndexByte(head, 0) >= 0 {
		return nil // binary
	}
	var out []finding.Finding
	s := bufio.NewScanner(br)
	s.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := s.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, sc.Line(line, scan.Meta{Source: source, Location: location, Line: lineNo})...)
	}
	return out
}

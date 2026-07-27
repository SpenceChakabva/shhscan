package sources

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/SpenceChakabva/shhscan/internal/finding"
	"github.com/SpenceChakabva/shhscan/internal/scan"
)

// Git walks the full commit history of the repository at dir and scans every
// added line of every diff — the point of a history scanner is that a secret
// deleted in a later commit is still sitting in an old one. maxCommits caps the
// depth (0 = unlimited).
func Git(sc *scan.Scanner, dir string, maxCommits int) ([]finding.Finding, error) {
	if err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return nil, fmt.Errorf("%s is not a git repository", dir)
	}

	// %x00 = NUL, an unambiguous field separator that can't appear in a line.
	args := []string{"-C", dir, "log", "--all", "--no-merges", "--no-color", "-p", "-U0",
		"--pretty=format:__COMMIT__%x00%H%x00%an%x00%ad"}
	if maxCommits > 0 {
		args = append(args, "--max-count="+strconv.Itoa(maxCommits))
	}
	cmd := exec.Command("git", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var out []finding.Finding
	var commit, shortSha, author, date, file string
	fileExcluded := false
	newLine := 0

	sr := bufio.NewScanner(stdout)
	sr.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // tolerate long minified lines
	for sr.Scan() {
		line := sr.Text()
		switch {
		case strings.HasPrefix(line, "__COMMIT__\x00"):
			f := strings.Split(line, "\x00")
			if len(f) >= 4 {
				commit, author, date = f[1], f[2], f[3]
				shortSha = commit
				if len(shortSha) > 8 {
					shortSha = shortSha[:8]
				}
			}
		case strings.HasPrefix(line, "+++ b/"):
			file = strings.TrimPrefix(line, "+++ b/")
			fileExcluded = sc.Excluded(file)
		case strings.HasPrefix(line, "@@"):
			newLine = parseHunkNewStart(line)
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			if fileExcluded {
				newLine++
				continue
			}
			content := line[1:]
			meta := scan.Meta{
				Source: "git", Location: file, Line: newLine,
				Commit: shortSha, Author: author, Date: date,
			}
			out = append(out, sc.Line(content, meta)...)
			newLine++
		}
	}
	if err := sr.Err(); err != nil {
		return out, err
	}
	return out, cmd.Wait()
}

// parseHunkNewStart pulls c out of a hunk header "@@ -a,b +c,d @@".
func parseHunkNewStart(h string) int {
	plus := strings.Index(h, "+")
	if plus < 0 {
		return 0
	}
	rest := h[plus+1:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		end = len(rest)
	}
	n, _ := strconv.Atoi(rest[:end])
	return n
}

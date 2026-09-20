// Package buildinfo exposes version and build metadata.
//
// Values are injected at link time with -X for release builds and fall back
// to the Go build stamps recorded by the toolchain, so a `go build` from a
// checkout still reports its commit instead of claiming an unknown build.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Name is the program name.
const Name = "janitor"

// Injected at link time:
//
//	-X github.com/gitmoot/workspace-janitor/internal/buildinfo.version=v0.1.0
var (
	version   = ""
	commit    = ""
	buildDate = ""
)

// Info is the resolved build metadata.
type Info struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	CommitTime string `json:"commit_time,omitempty"`
	Modified   bool   `json:"modified"`
	BuildDate  string `json:"build_date,omitempty"`
	GoVersion  string `json:"go_version"`
	Platform   string `json:"platform"`
	CGOEnabled bool   `json:"cgo_enabled"`
}

// Get resolves build metadata for this binary.
func Get() Info {
	info := Info{
		Name:      Name,
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		settings := make(map[string]string, len(bi.Settings))
		for _, s := range bi.Settings {
			settings[s.Key] = s.Value
		}
		if info.Version == "" {
			info.Version = releaseVersion(bi.Main.Version)
		}
		if info.Commit == "" {
			info.Commit = settings["vcs.revision"]
		}
		info.CommitTime = settings["vcs.time"]
		info.Modified = settings["vcs.modified"] == "true"
		info.CGOEnabled = settings["CGO_ENABLED"] == "1"
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
}

// String renders a single-line summary.
func (i Info) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", i.Name, i.Version)
	if i.Commit != "" {
		short := i.Commit
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Fprintf(&b, " (%s", short)
		if i.Modified {
			b.WriteString("-dirty")
		}
		b.WriteString(")")
	}
	fmt.Fprintf(&b, " %s %s cgo=%t", i.GoVersion, i.Platform, i.CGOEnabled)
	return b.String()
}

// releaseVersion keeps a real module release version and discards the
// pseudo-version the toolchain synthesizes for an untagged checkout: a
// synthetic "v0.0.0-<date>-<commit>" would look like a release that does not
// exist. Such builds report "dev" plus the VCS commit instead.
func releaseVersion(v string) string {
	if v == "" || v == "(devel)" || strings.HasPrefix(v, "v0.0.0-") {
		return ""
	}
	return v
}

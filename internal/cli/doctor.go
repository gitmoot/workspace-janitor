package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gitmoot/workspace-janitor/internal/buildinfo"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// checkStatus is the outcome of one doctor check.
type checkStatus string

const (
	checkOK   checkStatus = "ok"
	checkWarn checkStatus = "warn"
	checkFail checkStatus = "fail"
)

// checkResult is one reported check.
type checkResult struct {
	Name   string      `json:"name"`
	Status checkStatus `json:"status"`
	Detail string      `json:"detail"`
}

// doctorReport is the `doctor` result contract.
type doctorReport struct {
	Build    buildinfo.Info `json:"build"`
	Paths    config.Paths   `json:"paths"`
	Checks   []checkResult  `json:"checks"`
	Failures int            `json:"failures"`
	Healthy  bool           `json:"healthy"`
}

// runDoctor verifies that this installation can actually work: directories
// exist and are writable, the policy parses, and the state database opens at
// the expected schema version. Checks report what was observed; none of them
// reports success for a step that did not run.
func runDoctor(ctx context.Context, e *env) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	report := doctorReport{Build: e.buildRef, Paths: paths}
	add := func(name string, status checkStatus, format string, args ...any) {
		report.Checks = append(report.Checks, checkResult{Name: name, Status: status, Detail: fmt.Sprintf(format, args...)})
	}

	if err := config.EnsureDirs(paths); err != nil {
		add("directories", checkFail, "%v", err)
	} else {
		for _, dir := range []struct{ name, path string }{
			{"config-dir", paths.ConfigDir},
			{"state-dir", paths.StateDir},
			{"cache-dir", paths.CacheDir},
		} {
			if err := checkWritable(dir.path); err != nil {
				add(dir.name, checkFail, "%s is not writable: %v", dir.path, err)
				continue
			}
			add(dir.name, checkOK, "%s is writable", dir.path)
		}
	}

	if policy, err := e.loadPolicy(); err != nil {
		add("policy", checkFail, "%v", err)
	} else {
		add("policy", checkOK, "%s: version %d, %d root(s), %d cache rule(s), jev=%s",
			policy.Source, policy.Version, len(policy.Roots), len(policy.Caches), jevSummary(policy))
	}

	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		add("store", checkFail, "%v", err)
	} else {
		stats, statsErr := db.Stats(ctx)
		if statsErr != nil {
			add("store", checkFail, "%v", statsErr)
		} else if stats.SchemaVersion != store.SchemaVersion() {
			add("store", checkFail, "%s is at schema %d, expected %d", paths.DatabaseFile, stats.SchemaVersion, store.SchemaVersion())
		} else {
			add("store", checkOK, "%s at schema %d (%d scan(s), %d inventory entrie(s), %d plan(s))",
				paths.DatabaseFile, stats.SchemaVersion, stats.Scans, stats.InventoryEntries, stats.Plans)
		}
		if closeErr := db.Close(); closeErr != nil {
			add("store-close", checkFail, "%v", closeErr)
		}
	}

	if e.buildRef.CGOEnabled {
		add("static-build", checkWarn, "this binary was built with cgo enabled; release builds must set CGO_ENABLED=0")
	} else {
		add("static-build", checkOK, "built without cgo")
	}

	for _, check := range report.Checks {
		if check.Status == checkFail {
			report.Failures++
		}
	}
	report.Healthy = report.Failures == 0

	if format == output.FormatJSON {
		if err := output.WriteJSON(e.stdout, "doctor", report); err != nil {
			return err
		}
	} else if err := writeDoctorText(e, report); err != nil {
		return err
	}
	if !report.Healthy {
		return fmt.Errorf("doctor found %d failing check(s)", report.Failures)
	}
	return nil
}

func writeDoctorText(e *env, report doctorReport) error {
	rows := make([][]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		rows = append(rows, []string{string(check.Status), check.Name, check.Detail})
	}
	if err := output.WriteTable(e.stdout, []string{"STATUS", "CHECK", "DETAIL"}, rows); err != nil {
		return err
	}
	summary := "healthy"
	if !report.Healthy {
		summary = strconv.Itoa(report.Failures) + " failing check(s)"
	}
	_, err := fmt.Fprintf(e.stdout, "\n%s\n", summary)
	return err
}

// checkWritable proves the directory accepts a write, rather than inferring
// it from permission bits that may not reflect the mount or the filesystem.
func checkWritable(dir string) error {
	if dir == "" {
		return fmt.Errorf("no directory resolved")
	}
	f, err := os.CreateTemp(dir, ".janitor-write-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	closeErr := f.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return closeErr
	}
	if removeErr != nil {
		return fmt.Errorf("probe file %s could not be removed: %w", filepath.Base(name), removeErr)
	}
	return nil
}

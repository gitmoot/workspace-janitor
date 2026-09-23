package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func serviceGenerateCommand() *command {
	return &command{
		name: "generate", usage: "janitor service generate --output DIR --binary ABSOLUTE_PATH",
		summary: "Write disabled-by-default user units to an explicit directory; never call systemctl",
		register: func(fs *flag.FlagSet) func(context.Context, *env, []string) error {
			output := fs.String("output", "", "absolute destination for generated units")
			binary := fs.String("binary", "", "absolute janitor executable for ExecStart")
			return func(ctx context.Context, e *env, args []string) error {
				return runServiceGenerate(ctx, e, args, *output, *binary)
			}
		},
	}
}

func runServiceGenerate(_ context.Context, e *env, args []string, output, binary string) error {
	if len(args) != 0 {
		return &usageError{msg: "service generate takes no arguments"}
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(output) || !safeUnitArg(binary) || !safeUnitArg(paths.PolicyFile) {
		return &usageError{msg: "--output must be absolute; binary and policy must be absolute paths without systemd control characters"}
	}
	info, err := os.Stat(binary)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("--binary must name an executable regular file")
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(output); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output must be a real directory: %v", err)
	}
	units := []struct{ name, body string }{
		{"janitor-watch.service", fmt.Sprintf(`[Unit]
Description=Workspace Janitor top-level inventory watcher

[Service]
Type=simple
ExecStart=%s --policy %s watch
Environment=OPENROUTER_API_KEY=
NoNewPrivileges=true
IPAddressDeny=any
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=default.target
`, binary, paths.PolicyFile)},
		{"janitor-cycle.service", fmt.Sprintf(`[Unit]
Description=Workspace Janitor daily prevention cycle

[Service]
Type=oneshot
ExecStart=%s --policy %s cycle
Environment=OPENROUTER_API_KEY=
NoNewPrivileges=true
IPAddressDeny=any
`, binary, paths.PolicyFile)},
		{"janitor-cycle.timer", `[Unit]
Description=Workspace Janitor daily scan and retention check

[Timer]
OnCalendar=daily
Persistent=true
Unit=janitor-cycle.service

[Install]
WantedBy=timers.target
`},
	}
	for _, unit := range units {
		if _, err := os.Lstat(filepath.Join(output, unit.name)); err == nil {
			return fmt.Errorf("unit %s already exists; refusing overwrite", unit.name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, unit := range units {
		file, err := os.OpenFile(filepath.Join(output, unit.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString(unit.body)
		if syncErr := file.Sync(); writeErr == nil {
			writeErr = syncErr
		}
		if closeErr := file.Close(); writeErr == nil {
			writeErr = closeErr
		}
		if writeErr != nil {
			return writeErr
		}
		if _, err := fmt.Fprintln(e.stdout, filepath.Join(output, unit.name)); err != nil {
			return err
		}
	}
	return nil
}

func safeUnitArg(path string) bool {
	return filepath.IsAbs(path) && !strings.ContainsAny(path, " \t\n\r%\"\\;'")
}

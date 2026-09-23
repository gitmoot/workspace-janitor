// Package cli implements the janitor command tree.
//
// Environment lookups are injected so fixture runs cannot reach the
// operator's real configuration or state.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/buildinfo"
	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/output"
)

// ExitCode is the process exit status.
type ExitCode int

const (
	// ExitOK means the command completed.
	ExitOK ExitCode = 0
	// ExitError means the command ran and failed.
	ExitError ExitCode = 1
	// ExitUsage means the invocation was rejected before any work happened.
	ExitUsage ExitCode = 2
)

// Options configures one CLI run.
type Options struct {
	// Args are the arguments after the program name.
	Args []string
	// Stdout receives command results; Stderr receives diagnostics.
	Stdout io.Writer
	Stderr io.Writer
	// Lookup resolves environment variables. Required: there is no implicit
	// fallback to the real environment.
	Lookup config.Lookup
	// AgentSources are registered-agent adapters consulted during a scan.
	// The binary ships with none: an agent registry is an integration, and
	// a scan must work with no registry at all.
	AgentSources []collect.AgentSource
}

// globalOpts are the flags accepted before and after the command name.
type globalOpts struct {
	configDir string
	stateDir  string
	cacheDir  string
	policy    string
	format    string
}

func (g *globalOpts) register(fs *flag.FlagSet) {
	fs.StringVar(&g.configDir, "config-dir", g.configDir, "configuration directory (default: XDG config home)")
	fs.StringVar(&g.stateDir, "state-dir", g.stateDir, "state directory holding the database and quarantine (default: XDG state home)")
	fs.StringVar(&g.cacheDir, "cache-dir", g.cacheDir, "cache directory (default: XDG cache home)")
	fs.StringVar(&g.policy, "policy", g.policy, "policy file (default: <config-dir>/policy.yaml)")
	fs.StringVar(&g.format, "format", g.format, "output format: text or json")
}

// env is the resolved execution context of one command.
type env struct {
	opts   *globalOpts
	stdout io.Writer
	stderr io.Writer
	lookup config.Lookup

	agentSources []collect.AgentSource

	paths    *config.Paths
	policy   *config.Policy
	buildRef buildinfo.Info
}

// format returns the validated output format.
func (e *env) format() (output.Format, error) {
	f, err := output.ParseFormat(e.opts.format)
	if err != nil {
		return "", &usageError{msg: err.Error()}
	}
	return f, nil
}

// resolvePaths resolves and caches the locations for this run.
func (e *env) resolvePaths() (config.Paths, error) {
	if e.paths != nil {
		return *e.paths, nil
	}
	paths, err := config.ResolvePaths(e.lookup, config.Overrides{
		ConfigDir:  e.opts.configDir,
		StateDir:   e.opts.stateDir,
		CacheDir:   e.opts.cacheDir,
		PolicyFile: e.opts.policy,
	})
	if err != nil {
		return config.Paths{}, err
	}
	e.paths = &paths
	return paths, nil
}

// loadPolicy loads and caches the policy for this run.
func (e *env) loadPolicy() (config.Policy, error) {
	if e.policy != nil {
		return *e.policy, nil
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return config.Policy{}, err
	}
	policy, err := config.LoadPolicy(paths)
	if err != nil {
		return config.Policy{}, err
	}
	e.policy = &policy
	return policy, nil
}

// command is one node of the command tree. A node is either a leaf with a
// register function or a group with subcommands.
type command struct {
	name        string
	usage       string
	summary     string
	long        string
	subcommands []*command

	// register binds this command's flags to fs and returns its runner.
	register func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error
}

func (c *command) find(name string) *command {
	for _, sub := range c.subcommands {
		if sub.name == name {
			return sub
		}
	}
	return nil
}

// usageError rejects an invocation before any work is done.
type usageError struct {
	msg string
	cmd *command
}

func (e *usageError) Error() string { return e.msg }

// Run executes one CLI invocation and returns the process exit code.
func Run(ctx context.Context, opts Options) ExitCode {
	stdout := opts.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	if opts.Lookup == nil {
		fmt.Fprintln(stderr, "janitor: internal error: no environment lookup was provided")
		return ExitError
	}

	root := rootCommand()
	global := &globalOpts{format: string(output.FormatText)}
	e := &env{
		opts:         global,
		stdout:       stdout,
		stderr:       stderr,
		lookup:       opts.Lookup,
		agentSources: opts.AgentSources,
		buildRef:     buildinfo.Get(),
	}

	fs := newFlagSet(buildinfo.Name)
	global.register(fs)
	showVersion := fs.Bool("version", false, "print version information and exit")
	if err := fs.Parse(opts.Args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeRootHelp(stdout, root, global)
			return ExitOK
		}
		fmt.Fprintf(stderr, "janitor: %v\n\n", err)
		writeRootHelp(stderr, root, global)
		return ExitUsage
	}
	if *showVersion {
		return report(e, runVersion(ctx, e))
	}

	args := fs.Args()
	if len(args) == 0 {
		writeRootHelp(stderr, root, global)
		fmt.Fprintln(stderr, "\njanitor: no command given")
		return ExitUsage
	}
	if args[0] == "help" {
		return runHelp(stdout, stderr, root, global, args[1:])
	}
	return report(e, dispatch(ctx, root, e, global, args))
}

// dispatch resolves args against the command tree and runs the selected leaf.
func dispatch(ctx context.Context, parent *command, e *env, global *globalOpts, args []string) error {
	name := args[0]
	cmd := parent.find(name)
	if cmd == nil {
		return &usageError{msg: fmt.Sprintf("unknown command %q", commandPath(parent, name)), cmd: parent}
	}
	rest := args[1:]
	if len(cmd.subcommands) > 0 {
		if len(rest) == 0 {
			return &usageError{msg: fmt.Sprintf("%q requires a subcommand", cmd.name), cmd: cmd}
		}
		if isHelpFlag(rest[0]) {
			writeCommandHelp(e.stdout, cmd, global)
			return nil
		}
		return dispatch(ctx, cmd, e, global, rest)
	}

	fs := newFlagSet(cmd.usage)
	run := cmd.register(fs)
	global.register(fs)
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeCommandHelp(e.stdout, cmd, global)
			return nil
		}
		return &usageError{msg: err.Error(), cmd: cmd}
	}
	return run(ctx, e, fs.Args())
}

// report renders an error and maps it to an exit code.
func report(e *env, err error) ExitCode {
	if err == nil {
		return ExitOK
	}
	var usage *usageError
	if errors.As(err, &usage) {
		fmt.Fprintf(e.stderr, "janitor: %v\n", usage)
		if usage.cmd != nil {
			fmt.Fprintln(e.stderr)
			writeCommandHelp(e.stderr, usage.cmd, e.opts)
		}
		return ExitUsage
	}
	var cfgErr *config.Error
	if errors.As(err, &cfgErr) {
		fmt.Fprintf(e.stderr, "janitor: %v\n", cfgErr)
		return ExitUsage
	}
	fmt.Fprintf(e.stderr, "janitor: %v\n", err)
	return ExitError
}

func runHelp(stdout, stderr io.Writer, root *command, global *globalOpts, args []string) ExitCode {
	if len(args) == 0 {
		writeRootHelp(stdout, root, global)
		return ExitOK
	}
	cmd := root
	for _, name := range args {
		next := cmd.find(name)
		if next == nil {
			fmt.Fprintf(stderr, "janitor: unknown command %q\n\n", strings.Join(args, " "))
			writeRootHelp(stderr, root, global)
			return ExitUsage
		}
		cmd = next
	}
	writeCommandHelp(stdout, cmd, global)
	return ExitOK
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// Help and errors are rendered by this package so that every code path
	// produces the same layout.
	fs.SetOutput(io.Discard)
	return fs
}

func isHelpFlag(arg string) bool { return arg == "-h" || arg == "--help" || arg == "-help" }

func commandPath(parent *command, name string) string {
	if parent.name == buildinfo.Name {
		return name
	}
	return parent.name + " " + name
}

func writeRootHelp(w io.Writer, root *command, global *globalOpts) {
	fmt.Fprintf(w, "%s - safe, reversible workspace hygiene for developer and AI-agent machines\n\n", buildinfo.Name)
	fmt.Fprintf(w, "Usage:\n  %s [global flags] <command> [flags] [arguments]\n\n", buildinfo.Name)
	fmt.Fprintln(w, "Commands:")
	rows := make([][]string, 0, len(root.subcommands))
	for _, cmd := range root.subcommands {
		rows = append(rows, helpRow(cmd))
	}
	_ = output.WriteTable(w, nil, rows)
	fmt.Fprintln(w, "\nGlobal flags:")
	fmt.Fprint(w, globalFlagHelp(global))
	fmt.Fprintf(w, "\nRun \"%s help <command>\" for details.\n", buildinfo.Name)
}

func writeCommandHelp(w io.Writer, cmd *command, global *globalOpts) {
	fmt.Fprintf(w, "Usage:\n  %s\n\n", cmd.usage)
	if cmd.summary != "" {
		fmt.Fprintf(w, "%s\n", cmd.summary)
	}
	if cmd.long != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimRight(cmd.long, "\n"))
	}
	if len(cmd.subcommands) > 0 {
		fmt.Fprintln(w, "\nSubcommands:")
		rows := make([][]string, 0, len(cmd.subcommands))
		for _, sub := range cmd.subcommands {
			rows = append(rows, helpRow(sub))
		}
		_ = output.WriteTable(w, nil, rows)
	}
	if cmd.register != nil {
		fs := newFlagSet(cmd.usage)
		cmd.register(fs)
		if help := flagHelp(fs); help != "" {
			fmt.Fprintln(w, "\nFlags:")
			fmt.Fprint(w, help)
		}
	}
	fmt.Fprintln(w, "\nGlobal flags:")
	fmt.Fprint(w, globalFlagHelp(global))
}

func globalFlagHelp(global *globalOpts) string {
	fs := newFlagSet("global")
	global.register(fs)
	fs.Bool("version", false, "print version information and exit")
	return flagHelp(fs)
}

// flagHelp renders flags sorted by name, two-space indented.
func flagHelp(fs *flag.FlagSet) string {
	type entry struct{ name, usage string }
	var entries []entry
	fs.VisitAll(func(f *flag.Flag) {
		entries = append(entries, entry{name: f.Name, usage: f.Usage})
	})
	if len(entries) == 0 {
		return ""
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{"  --" + e.name, e.usage})
	}
	var b strings.Builder
	_ = output.WriteTable(&b, nil, rows)
	return b.String()
}

// helpRow renders one command row.
func helpRow(cmd *command) []string {
	return []string{"  " + cmd.usage, cmd.summary}
}

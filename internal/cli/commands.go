package cli

import (
	"context"
	"flag"

	"github.com/gitmoot/workspace-janitor/internal/buildinfo"
)

// rootCommand builds the command tree. Every command of the product contract
// is registered here from the start, including the ones later slices
// implement, so the interface is stable and `--help` never lies about what
// this build can do.
func rootCommand() *command {
	return &command{
		name:  buildinfo.Name,
		usage: "janitor [global flags] <command> [flags] [arguments]",
		subcommands: []*command{
			scanCommand(),
			planCommand(),
			explainCommand(),
			applyCommand(),
			restoreCommand(),
			statusCommand(),
			policyCommand(),
			doctorCommand(),
			versionCommand(),
		},
	}
}

// planned registers a command that exists in the contract but is not
// implemented by this build. Its flags are declared so the interface is
// reviewable, and running it always fails with ExitNotImplemented.
func planned(cmd *command, flags func(fs *flag.FlagSet)) *command {
	cmd.register = func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
		if flags != nil {
			flags(fs)
		}
		return func(context.Context, *env, []string) error {
			return &notImplementedError{command: cmd.name, tracking: cmd.tracking}
		}
	}
	return cmd
}

func scanCommand() *command {
	return &command{
		name:    "scan",
		usage:   "janitor scan [flags] [root...]",
		summary: "Inventory configured roots and collect safety evidence",
		long: "Walks each root with lstat metadata only, then collects Git state and\n" +
			"process, registered-agent, and service references. Every collector is\n" +
			"bounded, and anything it cannot observe is recorded as unknown evidence\n" +
			"that protects the path rather than as a clean result.\n\n" +
			"Deep sizing is opt-in: the default scan performs no recursive reads.\n" +
			"Given root arguments, each inherits the bounds of the policy root that\n" +
			"contains it.",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			opts := scanOptions{}
			fs.IntVar(&opts.maxDepth, "max-depth", 0, "override the per-root metadata walk depth")
			fs.IntVar(&opts.entriesLimit, "max-entries", 0, "override the total recorded entry limit")
			fs.BoolVar(&opts.deepSize, "deep-size", false, "compute bounded recursive directory sizes")
			fs.BoolVar(&opts.noGit, "no-git", false, "skip Git collection")
			fs.BoolVar(&opts.noProcesses, "no-processes", false, "skip process reference collection")
			fs.BoolVar(&opts.noServices, "no-services", false, "skip service and scheduler reference collection")
			fs.BoolVar(&opts.noPersist, "no-store", false, "report the inventory without writing it to the database")
			fs.BoolVar(&opts.noPriorScan, "no-compare", false, "skip fingerprint comparison with the previous scan")
			return func(ctx context.Context, e *env, args []string) error {
				return runScan(ctx, e, args, opts)
			}
		},
	}
}

func planCommand() *command {
	return planned(&command{
		name:     "plan",
		usage:    "janitor plan [flags]",
		summary:  "Turn the latest scan into a reviewable, reversible plan",
		tracking: "issue #7",
		long:     "Applies deterministic safety rules to a scan and emits proposed actions.",
	}, func(fs *flag.FlagSet) {
		fs.String("scan", "", "scan id to plan from (default: the most recent scan)")
		fs.Bool("jev", false, "allow the model classifier for ambiguous entries")
	})
}

func explainCommand() *command {
	return planned(&command{
		name:     "explain",
		usage:    "janitor explain [flags] <path>",
		summary:  "Show the evidence and rules behind a decision for one path",
		tracking: "issue #7",
		long:     "Prints every collected signal, protection, and rule that produced the recommendation.",
	}, func(fs *flag.FlagSet) {
		fs.String("plan", "", "plan id to explain against (default: the most recent plan)")
	})
}

func applyCommand() *command {
	return planned(&command{
		name:     "apply",
		usage:    "janitor apply [flags]",
		summary:  "Execute an approved plan through quarantine",
		tracking: "issue #4",
		long: "Re-validates every guard immediately before mutating, moves items to\n" +
			"quarantine rather than deleting them, and records a reversible receipt.",
	}, func(fs *flag.FlagSet) {
		fs.String("plan", "", "plan id to apply")
		fs.Bool("dry-run", true, "report what would change without mutating anything")
		fs.Bool("confirm", false, "required to perform mutations")
	})
}

func restoreCommand() *command {
	return planned(&command{
		name:     "restore",
		usage:    "janitor restore [flags] <receipt-id>",
		summary:  "Restore quarantined items from a receipt",
		tracking: "issue #4",
		long:     "Returns quarantined items to their recorded original locations.",
	}, func(fs *flag.FlagSet) {
		fs.Bool("confirm", false, "required to perform the restore")
	})
}

func statusCommand() *command {
	return &command{
		name:    "status",
		usage:   "janitor status [flags]",
		summary: "Report resolved paths, policy source, and stored state",
		long: "Shows which configuration, state, and cache directories this run uses,\n" +
			"where the policy came from, and what the local database contains.",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			return func(ctx context.Context, e *env, args []string) error {
				if len(args) > 0 {
					return &usageError{msg: "status takes no arguments"}
				}
				return runStatus(ctx, e)
			}
		},
	}
}

func policyCommand() *command {
	return &command{
		name:    "policy",
		usage:   "janitor policy <subcommand>",
		summary: "Inspect and validate the policy document",
		subcommands: []*command{
			{
				name:    "check",
				usage:   "janitor policy check [flags]",
				summary: "Validate the policy file and show the effective policy",
				long: "Rejects unknown fields and reports every invalid field at once.\n" +
					"With no policy file present, the built-in defaults are reported.",
				register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
					return func(ctx context.Context, e *env, args []string) error {
						if len(args) > 0 {
							return &usageError{msg: "policy check takes no arguments"}
						}
						return runPolicyCheck(ctx, e)
					}
				},
			},
		},
	}
}

func doctorCommand() *command {
	return &command{
		name:    "doctor",
		usage:   "janitor doctor [flags]",
		summary: "Check the local installation: directories, policy, and database",
		long: "Creates the configured directories when missing, opens the state\n" +
			"database, applies pending migrations, and reports each check.",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			return func(ctx context.Context, e *env, args []string) error {
				if len(args) > 0 {
					return &usageError{msg: "doctor takes no arguments"}
				}
				return runDoctor(ctx, e)
			}
		},
	}
}

func versionCommand() *command {
	return &command{
		name:    "version",
		usage:   "janitor version",
		summary: "Print version, build, and contract versions",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			return func(ctx context.Context, e *env, args []string) error {
				if len(args) > 0 {
					return &usageError{msg: "version takes no arguments"}
				}
				return runVersion(ctx, e)
			}
		},
	}
}

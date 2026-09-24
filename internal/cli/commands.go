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
			watchCommand(),
			cycleCommand(),
			advisoryCommand(),
			serviceCommand(),
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
	return &command{
		name:    "plan",
		usage:   "janitor plan [flags]",
		summary: "Turn the latest scan into a reviewable plan",
		long: "Applies deterministic rules to a scan and emits typed actions: keep,\n" +
			"relocate, quarantine, or investigate. Rules run in precedence order and\n" +
			"a disagreement between them always resolves to the safer action.\n\n" +
			"A plan is bound to the scan, the evidence, and the policy it was built\n" +
			"from, and is immutable once stored. Approving selects actions by id or\n" +
			"path; it never edits the plan.\n\n" +
			"Entries the rules leave ambiguous can be offered to pinned Jev via\n" +
			"OpenRouter when jev.enabled is true and an API key is in the environment\n" +
			"variable named by jev.api_key_env (default OPENROUTER_API_KEY). Only a\n" +
			"redacted, allowlisted projection is sent. The model may only propose\n" +
			"keep, quarantine, or investigate; its advice is accepted only when the\n" +
			"safety engine allows it and it is safer than the rules' choice. Without\n" +
			"a key the plan is built from rules alone.",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			opts := planOptions{approver: "operator"}
			fs.StringVar(&opts.scanID, "scan", "", "scan id to plan from (default: the most recent completed scan)")
			fs.StringVar(&opts.planID, "plan", "", "load a stored plan instead of building one")
			fs.StringVar(&opts.approve, "approve", "", "comma-separated action ids or paths to approve")
			fs.BoolVar(&opts.approveAll, "approve-all", false, "approve every mutating action in the plan")
			fs.StringVar(&opts.approver, "approver", "operator", "who is recorded as approving")
			fs.StringVar(&opts.note, "note", "", "note stored with the approval")
			fs.BoolVar(&opts.noPersist, "no-store", false, "report the plan without storing it (model usage is still recorded)")
			fs.BoolVar(&opts.noJev, "no-jev", false, "plan from rules alone, even when the model is enabled")
			fs.BoolVar(&opts.jevDryRun, "jev-dry-run", false, "show the exact model requests without sending them (implies --no-store)")
			fs.BoolVar(&opts.jevDebug, "jev-debug", false, "also show the exact model requests that were sent")
			return func(ctx context.Context, e *env, args []string) error {
				return runPlan(ctx, e, args, opts)
			}
		},
	}
}

func explainCommand() *command {
	return &command{
		name:    "explain",
		usage:   "janitor explain [flags] <path>",
		summary: "Show the evidence and rules behind a decision for one path",
		long: "Traces one action: the rules that won, the alternatives that were\n" +
			"rejected and why, the collected evidence, the safety verdict, and\n" +
			"whether the action has been approved.",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			opts := explainOptions{}
			fs.StringVar(&opts.planID, "plan", "", "plan id to explain against (default: the most recent plan)")
			return func(ctx context.Context, e *env, args []string) error {
				return runExplain(ctx, e, args, opts)
			}
		},
	}
}
func applyCommand() *command {
	return &command{
		name:    "apply",
		usage:   "janitor apply (--quarantine | --expire | --prune --action ID) [flags]",
		summary: "Preview or perform approved cleanup, expiry, or official dedicated-cache pruning",
		long:    "Dry-run is the default. Quarantine is reversible; expiry needs policy opt-in. Official prune is irreversible and requires an approved action, an explicitly dedicated cache, a configured executable, confirmation, and a bounded runtime.",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			opts := applyOptions{dryRun: true}
			fs.BoolVar(&opts.prune, "prune", false, "run an approved provider command for an explicitly dedicated cache")
			fs.StringVar(&opts.actionID, "action", "", "approved action ID (required for --prune)")
			fs.StringVar(&opts.planID, "plan", "", "stored plan id (default: latest)")
			fs.StringVar(&opts.cleanupID, "cleanup", "", "expiry scan restricted to one receipt id")
			fs.BoolVar(&opts.quarantine, "quarantine", false, "move approved actions into quarantine")
			fs.BoolVar(&opts.expire, "expire", false, "scan quarantined receipts for expiry")
			fs.BoolVar(&opts.dryRun, "dry-run", true, "show proposed moves or deletions without mutating")
			fs.BoolVar(&opts.confirm, "confirm", false, "required for every filesystem mutation")
			return func(ctx context.Context, e *env, args []string) error { return runApply(ctx, e, args, opts) }
		},
	}
}

func watchCommand() *command {
	return &command{
		name: "watch", usage: "janitor watch",
		summary:  "Watch configured top-level roots and reconcile bounded inventory snapshots; never clean up",
		register: func(*flag.FlagSet) func(context.Context, *env, []string) error { return runWatch },
	}
}
func cycleCommand() *command {
	return &command{
		name: "cycle", usage: "janitor cycle",
		summary:  "Run the daily offline inventory, weekly deep scan when due, disk alerts, and opt-in expiry",
		register: func(*flag.FlagSet) func(context.Context, *env, []string) error { return runCycle },
	}
}

func serviceCommand() *command {
	return &command{
		name: "service", usage: "janitor service generate --output DIR --binary ABSOLUTE_PATH",
		summary:     "Generate but do not install Linux user service and timer files",
		subcommands: []*command{serviceGenerateCommand()},
	}
}

func restoreCommand() *command {
	return &command{
		name:    "restore",
		usage:   "janitor restore [--confirm] <cleanup-id>",
		summary: "Restore quarantined items without overwriting occupied paths",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			confirm := fs.Bool("confirm", false, "required to perform the restore")
			return func(ctx context.Context, e *env, args []string) error { return runRestore(ctx, e, args, *confirm) }
		},
	}
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

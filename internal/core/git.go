package core

// GitIsolationArgs returns the global Git options every Janitor Git command
// starts with. Object and history lookups then see only the repository's
// real objects and parents: replace refs (`git replace`) and a forged
// commit-graph could otherwise make an unpublished commit look published or
// resolve a path at a published commit to an unpublished blob. Status never
// runs an fsmonitor or a hook. Git's -c options override repository config.
func GitIsolationArgs() []string {
	return []string{"--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.commitGraph=false"}
}

// GitIsolationEnv returns the environment entries every Janitor Git command
// adds to an otherwise empty environment. Callers never inherit the caller's
// environment, so GIT_DIR, GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES
// and similar redirections never apply. The deprecated info/grafts file
// rewrites parents even under --no-replace-objects, so Git is pointed at a
// graft file that cannot exist (a path below /dev/null): an existing empty
// file would still print a deprecation hint on every command.
func GitIsolationEnv() []string {
	return []string{"GIT_NO_REPLACE_OBJECTS=1", "GIT_GRAFT_FILE=/dev/null/grafts"}
}

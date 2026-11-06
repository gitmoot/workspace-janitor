package collect

import (
	"slices"
	"testing"
)

// Review of #166: every valid pipeline path form must protect its folder.
// A miss reads as "not in use" and lets the folder be removed.
func TestSpecPathReferencesFindsEveryPathForm(t *testing.T) {
	spec := `
env:
  PIPE_HOME: /work/env-home
stages:
  - cwd: /work/pipeline bundle
    cmd: bash "/work/quoted dir/run.sh" --top 20
  - cmd: env --chdir=/work/chdir bash ./run.sh
  - cmd: R=/work/assigned PATH=/work/bin1:/work/bin2 sh -c 'cd /work/single && ./x' >/work/out.log
  - cmd: python3 /work/plain/run.py;echo done|tee /work/tee.txt
  - cmd: base=/work/base; bash "$base/pipelines/run.sh"
  - cmd: bash "${PIPELINE_DIR:-/work/fallback/pipelines}/run.sh"
  - cmd: cat "$PIPE_HOME/conf"
  - cmd: ls /work/runs/$(date +%F)/out
    description: "Prose that isn't a path: don't match it"
`
	refs, unresolved, err := specPathReferences(spec, "s", "d")
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("resolvable spec reported unresolved words: %q", unresolved)
	}
	exact := map[string]bool{}
	subtree := map[string]bool{}
	for _, ref := range refs {
		if ref.Subtree {
			subtree[ref.Path] = true
		} else {
			exact[ref.Path] = true
		}
	}
	for _, want := range []string{
		"/work/pipeline bundle", "/work/quoted dir/run.sh", "/work/chdir", "/work/assigned",
		"/work/bin1", "/work/bin2", "/work/out.log", "/work/plain/run.py", "/work/tee.txt",
		"/work/single", "/work/base/pipelines/run.sh", "/work/fallback/pipelines/run.sh", "/work/env-home/conf",
	} {
		if !exact[want] {
			t.Errorf("missing %q", want)
		}
	}
	// $(date) cannot be resolved; everything under its literal directory is.
	if !subtree["/work/runs"] {
		t.Errorf("command substitution did not protect /work/runs as a subtree: %v", subtree)
	}
}

// A constructed path with no known absolute prefix is unresolved, and the
// collector must treat the whole source as unknown rather than as "no paths".
func TestSpecPathReferencesReportsUnresolvablePaths(t *testing.T) {
	_, unresolved, err := specPathReferences("cmd: bash \"$UNSET_DIR/run.sh\"\n", "s", "d")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(unresolved, "$UNSET_DIR/run.sh") {
		t.Fatalf("unresolvable path not reported: %q", unresolved)
	}
}

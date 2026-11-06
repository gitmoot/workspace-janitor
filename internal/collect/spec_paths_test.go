package collect

import "testing"

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
  - cmd: EMPTY_DIR=; bash "${EMPTY_DIR:-/work/empty-fallback}/run.sh"
  - cmd: cat "$PIPE_HOME/conf"
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
	for _, ref := range refs {
		exact[ref.Path] = true
	}
	for _, want := range []string{
		"/work/pipeline bundle", "/work/quoted dir/run.sh", "/work/chdir", "/work/assigned",
		"/work/bin1", "/work/bin2", "/work/out.log", "/work/plain/run.py", "/work/tee.txt",
		"/work/single", "/work/base/pipelines/run.sh", "/work/fallback/pipelines/run.sh", "/work/env-home/conf",
		"/work/empty-fallback/run.sh",
	} {
		if !exact[want] {
			t.Errorf("missing %q", want)
		}
	}
}

// A path built from a value the spec does not state may point anywhere,
// ".." included, so no literal prefix bounds it: the collector must treat
// the whole source as unknown rather than as "no paths".
func TestSpecPathReferencesReportsUnresolvablePaths(t *testing.T) {
	for _, spec := range []string{
		`cmd: bash "$UNSET_DIR/run.sh"`,
		`cmd: ls /work/runs/$(date +%F)/out`,
		`cmd: bash "/work/$UNSET/../../pipelines/run.sh"`,
	} {
		_, unresolved, err := specPathReferences(spec+"\n", "s", "d")
		if err != nil {
			t.Fatal(err)
		}
		if len(unresolved) == 0 {
			t.Errorf("%s: unresolvable path not reported", spec)
		}
	}
}

// Reviews of #166 rounds 4 and 5: expansions beyond the result cap, or a
// variable with more values than recorded, must never drop a candidate
// silently, nor fall back to a literal prefix that ".." can escape: the word
// is unresolved.
func TestSpecPathReferencesNeverTruncatesExpansions(t *testing.T) {
	for name, spec := range map[string]string{
		"cap":     `cmd: A=a0; A=a1; A=a2; A=a3; B=b0; B=b1; B=b2; B=b3; bash "/work/${A:-fa}-${B:-fb}/run.sh"`,
		"values":  `cmd: X=1; X=2; X=3; X=4; X=5; X=6; X=7; X=8; X=9; bash "/work/x$X/run.sh"`,
		"escapes": `cmd: A=a0; A=a1; A=a2; A=a3; B=b0; B=b1; B=b2; B=b3; bash "/work/${A:-fa}-${B:-fb}/../../pipelines/run.sh"`,
	} {
		_, unresolved, err := specPathReferences(spec+"\n", "s", "d")
		if err != nil {
			t.Fatal(err)
		}
		if len(unresolved) == 0 {
			t.Fatalf("%s: over-limit expansion was not reported unresolved", name)
		}
	}
}

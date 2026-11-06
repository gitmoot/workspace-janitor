package collect

import (
	"context"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"
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
  - cmd: EMPTY_DIR=; bash "${EMPTY_DIR:-/work/empty-fallback}/run.sh"
  - cmd: cat "$PIPE_HOME/conf"
    description: "Prose that isn't a path: don't match it"
`
	refs, unresolved, err := specPathReferences(spec, "s", "d", nil)
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
		_, unresolved, err := specPathReferences(spec+"\n", "s", "d", nil)
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
		_, unresolved, err := specPathReferences(spec+"\n", "s", "d", nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(unresolved) == 0 {
			t.Fatalf("%s: over-limit expansion was not reported unresolved", name)
		}
	}
}

// Post-merge review of #166: a shell expands globs, braces and a leading ~
// in a command's paths, so a pattern naming an existing directory protects
// it. A pattern that cannot be expanded safely is unresolved.
func TestSpecPathReferencesExpandsPathnames(t *testing.T) {
	dir := t.TempDir()
	pipelines := filepath.Join(dir, "work", "pipelines")
	if err := os.MkdirAll(pipelines, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pipelines, "run.sh"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	for _, cmd := range []string{
		"bash " + dir + "/work/{pipelines,elsewhere}/run.sh",
		"bash ~/work/pipelines/run.sh",
	} {
		refs, unresolved, err := specPathReferences("cmd: "+cmd+"\n", "s", "d", nil)
		if err != nil || len(unresolved) != 0 {
			t.Fatalf("%s: err=%v unresolved=%q", cmd, err, unresolved)
		}
		found := false
		for _, ref := range refs {
			found = found || ref.Path == filepath.Join(pipelines, "run.sh")
		}
		if !found {
			t.Errorf("%s: %s not protected: %+v", cmd, pipelines, refs)
		}
	}
	// Text that is not a path, however brace-rich, is not a candidate.
	if _, unresolved, err := specPathReferences(`cmd: echo '[{id:1,q:What {id:2}' --flag={x`+"\n", "s", "d", nil); err != nil || len(unresolved) != 0 {
		t.Errorf("non-path text reported unresolved: err=%v %q", err, unresolved)
	}
	// Quoting is gone before expansion, so the literal word must stay a
	// candidate: a quoted '/work/{a,b}' names that directory itself.
	literal := filepath.Join(dir, "work", "{a,b}")
	refs, _, _ := specPathReferences("cmd: bash '"+literal+"/run.sh'\n", "s", "d", nil)
	keptLiteral := false
	for _, ref := range refs {
		keptLiteral = keptLiteral || ref.Path == filepath.Join(literal, "run.sh")
	}
	if !keptLiteral {
		t.Errorf("literal brace path dropped: %+v", refs)
	}
	// Globs are never resolved: any glob character in a path word blocks.
	for _, cmd := range []string{
		"bash " + dir + "/work/pipeline[s]/run.sh",
		"bash " + dir + "/work/pipelines*/run.sh",
		"bash " + dir + "/work/pipeline?/run.sh",
		"bash " + dir + "/work/pipe\\[l]ines/run.sh",
		"bash '" + dir + "/work/pipeline?/run.sh'",
		"bash " + dir + "/work/{a,{b,c}}/run.sh",
		"bash " + dir + "/work/{1..3}/run.sh",
		"bash " + dir + "/work/pipeline[!b]/run.sh",
		"bash " + dir + "/work/pipeline[^b]/run.sh",
		"bash " + dir + "/work/[[:alpha:]]ipelines/run.sh",
		"bash " + dir + "/work/[[=p=]]ipelines/run.sh",
		"bash " + dir + "/work/[[.p.]]ipelines/run.sh",
		"bash " + dir + "/work/[]p]ipelines/run.sh",
		"bash ~no-such-user-janitor/pipelines/run.sh",
		"bash ~+/pipelines/run.sh",
	} {
		_, unresolved, err := specPathReferences("cmd: "+cmd+"\n", "s", "d", nil)
		if err != nil || len(unresolved) == 0 {
			t.Errorf("%s: not reported unresolved (err=%v)", cmd, err)
		}
	}
}

// ~user takes that account's home from the user database, as a shell does.
func TestSpecPathReferencesExpandsNamedUserHome(t *testing.T) {
	account, err := user.Current()
	if err != nil || !filepath.IsAbs(account.HomeDir) {
		t.Skip("no current user home")
	}
	refs, unresolved, err := specPathReferences("cmd: bash ~"+account.Username+"/pipelines/run.sh\n", "s", "d", nil)
	if err != nil || len(unresolved) != 0 {
		t.Fatalf("err=%v unresolved=%q", err, unresolved)
	}
	want := filepath.Join(account.HomeDir, "pipelines", "run.sh")
	for _, ref := range refs {
		if ref.Path == want {
			return
		}
	}
	t.Fatalf("~%s/pipelines/run.sh did not resolve to %s: %+v", account.Username, want, refs)
}

// Stagehand sets $STAGEHAND_WORK to <state>/runs/<run id>/work: expanding it
// with the placeholder lets the collector fold the reference into
// <state>/runs. A literal ".." that leaves that directory is still visible.
func TestSpecPathReferencesUsesRunnerVariables(t *testing.T) {
	runtime := map[string]string{
		"STAGEHAND_WORK":   "/state/runs/" + stagehandRunPlaceholder + "/work",
		"STAGEHAND_RUN_ID": stagehandRunPlaceholder,
	}
	refs, unresolved, err := specPathReferences("cmd: tool --out \"$STAGEHAND_WORK/rows.json\"\n", "s", "d", runtime)
	if err != nil || len(unresolved) != 0 {
		t.Fatalf("err=%v unresolved=%q", err, unresolved)
	}
	if len(refs) == 0 || refs[0].Path != "/state/runs/"+stagehandRunPlaceholder+"/work/rows.json" {
		t.Fatalf("run work path not expanded: %+v", refs)
	}
	refs, unresolved, _ = specPathReferences("cmd: tool --run \"$STAGEHAND_RUN_ID\" --log \"/state/runs/$STAGEHAND_RUN_ID/log\"\n", "s", "d", runtime)
	if len(unresolved) != 0 {
		t.Fatalf("run id reported unresolved: %q", unresolved)
	}
	refs, _, _ = specPathReferences("cmd: cat \"$STAGEHAND_WORK/../../../etc/x\"\n", "s", "d", runtime)
	if len(refs) == 0 || refs[0].Path != "/state/etc/x" {
		t.Fatalf("escape from the run directory not visible after Clean: %+v", refs)
	}
}

// Review of #167: references folded into <state>/runs must protect every
// run below it, and a stagehand state directory with a space in its path is
// still a path. A one-line command in a cmd field is not one long path.
func TestStagehandRunReferencesProtectRunsAndSurviveSpaces(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "stagehand state")
	specs := filepath.Join(root, "specs")
	if err := os.MkdirAll(specs, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := "stages:\n  - cmd: /usr/bin/tool --out \"$STAGEHAND_WORK/rows.json\" --run \"$STAGEHAND_RUN_ID\"\n"
	if err := os.WriteFile(filepath.Join(specs, "p.yaml"), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := &Options{ServiceSources: ServiceSources{StagehandDirs: []string{specs}, StagehandStateDir: state}}
	report := &core.CollectorReport{Status: core.CollectorRan}
	refs := gatherStagehand(context.Background(), opts, report)
	if report.Status != core.CollectorRan || report.Unknowns != 0 {
		t.Fatalf("spec should resolve completely: %+v", report)
	}
	runs := filepath.Join(state, "runs")
	var folded *Reference
	for i := range refs {
		if refs[i].Path == runs {
			folded = &refs[i]
		}
	}
	if folded == nil {
		t.Fatalf("run work path with a space in the state dir was dropped: %+v", refs)
	}
	entries := []core.Entry{{Path: runs}, {Path: filepath.Join(runs, "42")}, {Path: filepath.Join(runs, "42", "work")}}
	attachReferences(entries, []Reference{*folded}, time.Now())
	for _, entry := range entries {
		if !entry.Protected() {
			t.Errorf("%s not protected by the folded run reference", entry.Path)
		}
	}
}

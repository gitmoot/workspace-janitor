package collect

import (
	"slices"
	"testing"
)

// Review of #166: valid pipeline path forms must each yield a reference;
// a miss is silently "not in use" and lets the folder be removed.
func TestSpecPathReferencesFindsEveryPathForm(t *testing.T) {
	spec := `
stages:
  - cwd: /work/pipeline bundle
    cmd: bash "/work/quoted dir/run.sh" --top 20
  - cmd: env --chdir=/work/chdir bash ./run.sh
  - cmd: R=/work/assigned PATH=/work/bin1:/work/bin2 sh -c 'cd /work/single && ./x' >/work/out.log
  - cmd: python3 /work/plain/run.py;echo done|tee /work/tee.txt
    description: "Prose that isn't a path: don't match it"
`
	refs, err := specPathReferences(spec, "s", "d")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ref := range refs {
		got = append(got, ref.Path)
	}
	for _, want := range []string{
		"/work/pipeline bundle", "/work/quoted dir/run.sh", "/work/chdir", "/work/assigned",
		"/work/bin1", "/work/bin2", "/work/out.log", "/work/plain/run.py", "/work/tee.txt",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	// 'cd /work/single && ./x' is one single-quoted word; its value is the
	// command passed to sh -c, so the path inside it must count too.
	if !slices.Contains(got, "/work/single") {
		t.Errorf("missing /work/single inside a quoted sh -c command: %q", got)
	}
}

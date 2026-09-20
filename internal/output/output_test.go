package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func TestWriteJSONEnvelopeIsStableAndVersioned(t *testing.T) {
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	plan := core.Plan{
		ID:             "plan-1",
		ScanID:         "scan-1",
		CreatedAt:      created,
		EvidenceDigest: "evidence-1",
		PolicyDigest:   "policy-1",
		Actions: []core.Action{{
			ID:         "action-1",
			Path:       "/repos/app/target",
			Kind:       core.ActionQuarantine,
			Class:      core.ClassGeneratedArtifact,
			Retention:  core.Retention30Days,
			Confidence: 0.75,
			Reasons:    []string{"regenerable build output"},
			CreatedAt:  created,
		}},
	}
	plan.Normalize()

	var first, second bytes.Buffer
	if err := WriteJSON(&first, "plan", plan); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if err := WriteJSON(&second, "plan", plan); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if first.String() != second.String() {
		t.Fatalf("output is not deterministic:\n%s\n---\n%s", first.String(), second.String())
	}

	// The exact document is the published contract: a field rename or
	// reordering must fail here rather than surprise a consumer.
	want := `{
  "schema_version": 1,
  "kind": "plan",
  "data": {
    "contract_version": 1,
    "id": "plan-1",
    "scan_id": "scan-1",
    "status": "draft",
    "created_at": "2026-02-03T04:05:06Z",
    "evidence_digest": "evidence-1",
    "policy_digest": "policy-1",
    "actions": [
      {
        "id": "action-1",
        "plan_id": "plan-1",
        "path": "/repos/app/target",
        "kind": "quarantine",
        "class": "generated_artifact",
        "retention": "30d",
        "confidence": 0.75,
        "status": "pending",
        "filesystem_id": {
          "device": 0,
          "inode": 0
        },
        "reasons": [
          "regenerable build output"
        ],
        "created_at": "2026-02-03T04:05:06Z"
      }
    ]
  }
}
`
	if first.String() != want {
		t.Errorf("plan document changed:\ngot:\n%s\nwant:\n%s", first.String(), want)
	}
}

func TestWriteJSONDoesNotEscapeHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, "probe", map[string]string{"path": "/repos/a&b<c>"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "/repos/a&b<c>") {
		t.Errorf("path was escaped: %s", buf.String())
	}
}

func TestParseFormat(t *testing.T) {
	for _, in := range []string{"text", "json"} {
		if _, err := ParseFormat(in); err != nil {
			t.Errorf("ParseFormat(%q): %v", in, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("expected an unknown format to be rejected")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:                      "0 B",
		512:                    "512 B",
		1024:                   "1.0 KiB",
		1536:                   "1.5 KiB",
		1024 * 1024:            "1.0 MiB",
		3 * 1024 * 1024 * 1024: "3.0 GiB",
	}
	for in, want := range cases {
		if got := HumanBytes(in); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteTableAlignsColumnsWithoutTrailingSpace(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, []string{"STATUS", "CHECK"}, [][]string{
		{"ok", "config-dir"},
		{"fail", "store"},
	}); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if strings.HasSuffix(line, " ") {
			t.Errorf("line %q has trailing whitespace", line)
		}
	}
	if !strings.Contains(buf.String(), "STATUS  CHECK") {
		t.Errorf("columns are not aligned:\n%s", buf.String())
	}
}

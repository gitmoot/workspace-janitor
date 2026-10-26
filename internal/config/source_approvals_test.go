package config

import (
	"strings"
	"testing"
)

func TestParseSourceNameApprovalScope(t *testing.T) {
	paths := fixturePaths(t)
	document := `version: 1
roots:
  - path: /repos
protect:
  name_patterns: ["*credentials*"]
source_name_approvals:
  generation: reviewed-1
  reviewers: [authorized-reviewer]
  files:
    - repository: /repos/app
      remote: https://github.com/example/app.git
      path: internal/credentials.go
      commit: "1111111111111111111111111111111111111111"
      blob: "2222222222222222222222222222222222222222"
      sha256: "3333333333333333333333333333333333333333333333333333333333333333"
      name_pattern: "*credentials*"
      reviewer: authorized-reviewer
      record: review://fixture/1
      generation: reviewed-1
      reviewed_at: 2026-10-26T12:00:00Z
      expires_at: 2026-10-27T12:00:00Z
`
	if _, err := parse(t, paths, document); err != nil {
		t.Fatalf("exact scoped approval rejected: %v", err)
	}
	for _, change := range []struct{ name, old, replacement string }{
		{"traversal", "internal/credentials.go", "../credentials.go"},
		{"secret_container", "internal/credentials.go", "credentials.json"},
		{"metadata", "internal/credentials.go", ".private/credentials.go"},
		{"unauthorized_reviewer", "reviewer: authorized-reviewer", "reviewer: different-reviewer"},
		{"generation", "generation: reviewed-1\n      reviewed_at", "generation: revoked\n      reviewed_at"},
		{"expiry", "2026-10-27T12:00:00Z", "2026-10-25T12:00:00Z"},
		{"remote_credentials", "https://github.com/example/app.git", "https://token@github.com/example/app.git"},
		{"pattern_scope", "name_pattern: \"*credentials*\"", "name_pattern: \"*\""},
		{"digest", strings.Repeat("3", 64), "invalid"},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := parse(t, paths, strings.Replace(document, change.old, change.replacement, 1)); err == nil {
				t.Fatal("invalid approval scope accepted")
			}
		})
	}
}

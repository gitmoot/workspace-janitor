package cli

import (
	"context"
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/buildinfo"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// versionReport is the `version` result contract. Contract and schema
// versions travel with the build version: a consumer needs all three to know
// whether it can read this build's output and state.
type versionReport struct {
	Build           buildinfo.Info `json:"build"`
	ContractVersion int            `json:"contract_version"`
	SchemaVersion   int            `json:"schema_version"`
}

func runVersion(ctx context.Context, e *env) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	report := versionReport{
		Build:           e.buildRef,
		ContractVersion: core.ContractVersion,
		SchemaVersion:   store.SchemaVersion(),
	}
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "version", report)
	}
	_, err = fmt.Fprintf(e.stdout, "%s contract=%d schema=%d\n", report.Build.String(), report.ContractVersion, report.SchemaVersion)
	return err
}

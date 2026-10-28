package collect

import (
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// EvidenceGap reports the first collector whose evidence is too incomplete
// to establish that nothing references or uses the observed paths, or nil.
// The filesystem, process and service collectors must have run; Git may be
// partial (an entry's own unknown Git state is blocked by the safety
// engine); Gitmoot must have run or found no Gitmoot home; registered-agent
// evidence counts only when agentSources are configured.
func EvidenceGap(reports []core.CollectorReport, agentSources bool) error {
	for _, report := range reports {
		switch report.Name {
		case CollectorFilesystem, CollectorProcesses, CollectorServices:
			if report.Status != core.CollectorRan {
				return fmt.Errorf("evidence incomplete: %s: %s", report.Name, report.Detail)
			}
		case CollectorGit:
			if report.Status != core.CollectorRan && report.Status != core.CollectorPartial {
				return fmt.Errorf("Git evidence incomplete: %s", report.Detail)
			}
		case CollectorGitmoot:
			if report.Status != core.CollectorRan && report.Status != core.CollectorSkipped {
				return fmt.Errorf("Gitmoot evidence incomplete: %s", report.Detail)
			}
		case CollectorAgents:
			if agentSources && report.Status != core.CollectorRan {
				return fmt.Errorf("agent evidence incomplete: %s", report.Detail)
			}
		}
	}
	return nil
}

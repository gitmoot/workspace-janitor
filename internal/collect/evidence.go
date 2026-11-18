package collect

import (
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// EvidenceGap reports the first collector whose evidence is too incomplete
// to establish that nothing references or uses the observed paths, or nil.
// The filesystem, process and service collectors must have run; Git may be
// partial (an entry's own unknown Git state is blocked by the safety
// engine); Gitmoot must have run or found no Gitmoot home; herdr must have
// run or been skipped (not configured, or no session root reached);
// registered-agent evidence counts only when agentSources are configured.
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
		case CollectorHerdr:
			if err := HerdrGap([]core.CollectorReport{report}); err != nil {
				return err
			}
		case CollectorAgents:
			if agentSources && report.Status != core.CollectorRan {
				return fmt.Errorf("agent evidence incomplete: %s", report.Detail)
			}
		}
	}
	return nil
}

// HerdrGap reports a herdr collector that was needed (collectors.herdr set,
// a session root reached) but gave no complete answer, or nil.
func HerdrGap(reports []core.CollectorReport) error {
	for _, report := range reports {
		if report.Name == CollectorHerdr && report.Status != core.CollectorRan && report.Status != core.CollectorSkipped {
			return fmt.Errorf("herdr agent session evidence incomplete, so no OMP session is touched: %s", report.Detail)
		}
	}
	return nil
}

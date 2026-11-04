package cli

import (
	"os"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Archive fixtures are tiny; the production 10 GB reserve would make them
// depend on the runner's free space (issue #143). Tests that check the
// reserve itself set core.AllocationReserveBytes explicitly.
func TestMain(m *testing.M) {
	core.AllocationReserveBytes = 1 << 20
	os.Exit(m.Run())
}

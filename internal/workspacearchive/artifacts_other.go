//go:build !linux

package workspacearchive

import (
	"context"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

type artifactState struct{}

// ArtifactRoot is unavailable off Linux.
type ArtifactRoot struct{}

func OpenArtifactRoot(string) (*ArtifactRoot, error) { return nil, errUnsupported }

func (r *ArtifactRoot) Close() {}

func (r *ArtifactRoot) Sessions(int) ([]string, error) { return nil, errUnsupported }

func (r *ArtifactRoot) ObserveSession(context.Context, string, []string, int) ([]ArtifactFile, []ArtifactSkip, error) {
	return nil, nil, errUnsupported
}

func (r *ArtifactRoot) CreateBatch(context.Context, config.WorkspaceArchiveCategoryDestination, string, string, []ArtifactFile, func() error) (ArtifactManifest, *Binding, error) {
	return ArtifactManifest{}, nil, errUnsupported
}

func CheckArtifacts(context.Context, config.WorkspaceArchiveCategoryDestination, Binding) (ArtifactManifest, error) {
	return ArtifactManifest{}, errUnsupported
}

func (r *ArtifactRoot) VerifyFile(context.Context, ArtifactMember) (VerifiedArtifact, error) {
	return VerifiedArtifact{}, errUnsupported
}

func VerifyArtifactCopy(context.Context, string, ArtifactMember) (VerifiedArtifact, error) {
	return VerifiedArtifact{}, errUnsupported
}

func OpenFiles(context.Context, string, []string) (map[string]string, error) {
	return nil, errUnsupported
}

func (r *ArtifactRoot) Same(ArtifactMember, VerifiedArtifact) error { return errUnsupported }

func SameCopy(string, VerifiedArtifact) error { return errUnsupported }

func SensitiveName(string, string, []string) bool { return true }

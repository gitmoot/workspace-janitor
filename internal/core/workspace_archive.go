package core

import "time"

// WorkspaceArchiveBinding pins a verified workspace archive whose manifest
// exactly matches the observed local tree. Like ExportArchiveBinding it
// travels with inventory and cleanup receipts and feeds the fingerprint, so a
// withdrawn pin or a changed tree cannot inherit local expiry authority.
type WorkspaceArchiveBinding struct {
	Manifest       string `json:"manifest"`
	ManifestSHA256 string `json:"manifest_sha256"`
	MemberCount    int    `json:"member_count"`
	// TreeDigest is the SHA-256 of the manifest member list, which the local
	// tree was verified to equal member for member.
	TreeDigest string `json:"tree_digest"`
	// CreatedAt is the pinned manifest's creation time; local retention is
	// measured from it.
	CreatedAt time.Time `json:"created_at"`
}

package core

// ExportArchiveBinding pins an independently retained, verified export archive.
// It travels with inventory and cleanup receipts; removing a policy rule cannot
// turn a quarantined sole copy into an ordinary disposable file.
type ExportArchiveBinding struct {
	Manifest       string `json:"manifest"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

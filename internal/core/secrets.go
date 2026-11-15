package core

import (
	"net/url"
	"path/filepath"
	"strings"
)

// The built-in secret screen: names that look like real credentials or
// private keys. It applies whatever the policy says, and a published copy in
// Git does not make such a file safe to move quietly.
var (
	secretNames    = []string{".env", ".netrc", ".pgpass", ".npmrc", ".pypirc", "service-account.json", "token.json"}
	secretPrefixes = []string{".env.", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
	secretSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".ppk", ".kdbx", ".keystore", ".jks"}
	secretExamples = []string{".env.example", ".env.sample", ".env.template"}
)

// BuiltinSecretName reports whether name, an entry directly inside parent,
// matches the built-in secret screen. Matching is case-insensitive.
func BuiltinSecretName(name, parent string) bool {
	low := strings.ToLower(name)
	for _, example := range secretExamples {
		if low == example {
			return false
		}
	}
	// certifi's cacert.pem is the public Mozilla CA bundle, not a secret.
	if low == "cacert.pem" && filepath.Base(parent) == "certifi" {
		return false
	}
	for _, exact := range secretNames {
		if low == exact {
			return true
		}
	}
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(low, prefix) {
			return true
		}
	}
	for _, suffix := range secretSuffixes {
		if strings.HasSuffix(low, suffix) {
			return true
		}
	}
	// credentials*.json, including credentials.json.
	return strings.HasPrefix(low, "credentials") && strings.HasSuffix(low, ".json")
}

// PublishedSecret is a built-in secret name that Git tracks unmodified at a
// published HEAD: a leak to rotate and remove from Git history, never a
// reason to archive quietly. It still refuses the tree that holds it.
type PublishedSecret struct {
	// Repository is the origin URL without any user information, or the
	// checkout path when there is no origin.
	Repository string `json:"repository"`
	// Path is the file's path inside the repository.
	Path string `json:"path"`
	// Head is the published HEAD commit that holds the file.
	Head string `json:"head"`
}

// RepositoryLabel names a repository for a report: its origin URL with any
// user information (which may carry a token) removed, or path without one.
func RepositoryLabel(origin, path string) string {
	if origin == "" {
		return path
	}
	if parsed, err := url.Parse(origin); err == nil && parsed.Scheme != "" && parsed.User != nil {
		parsed.User = nil
		return parsed.String()
	}
	return origin
}

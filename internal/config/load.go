package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"gopkg.in/yaml.v3"
)

// MaxPolicyBytes bounds how much of a policy file is read. A policy document
// is small; anything larger is a mistake or an attack, not configuration.
const MaxPolicyBytes = 1 << 20

// LoadPolicy reads and validates the policy for the resolved paths.
//
// A missing policy file is not an error: the built-in defaults are returned
// with FromFile false. An existing but invalid file always fails; defaults are
// never substituted for a broken document.
//
// The built-in defaults derive their single discovery root from the home
// directory. A run with no home — every path supplied by an override — has no
// default root, so it requires a policy file that declares one.
func LoadPolicy(paths Paths) (Policy, error) {
	if paths.PolicyFile == "" {
		return defaultsOnly(paths, "built-in defaults")
	}
	data, err := readPolicyFile(paths.PolicyFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return defaultsOnly(paths, fmt.Sprintf("built-in defaults (no policy file at %s)", paths.PolicyFile))
	case err != nil:
		return Policy{}, fmt.Errorf("read policy %s: %w", paths.PolicyFile, err)
	}
	return ParsePolicy(data, paths, paths.PolicyFile)
}

func defaultsOnly(paths Paths, source string) (Policy, error) {
	policy := DefaultPolicy(paths)
	policy.Source = source
	if len(policy.Roots) == 0 && paths.Home == "" {
		var errs core.FieldErrors
		errs.Add("roots", "cannot be derived without a home directory: write a policy file at %s declaring at least one root, or set %s",
			policyFileHint(paths), EnvHome)
		return Policy{}, &Error{Scope: source, Errors: errs}
	}
	if errs := policy.Validate(); len(errs) > 0 {
		return Policy{}, &Error{Scope: source, Errors: errs}
	}
	return policy, nil
}

func policyFileHint(paths Paths) string {
	if paths.PolicyFile != "" {
		return paths.PolicyFile
	}
	return "the configured policy path"
}

// ParsePolicy decodes and validates a policy document.
//
// Unknown fields are rejected: a typo must fail loudly rather than silently
// disable a protection the operator believed was configured. The document is
// decoded over the built-in defaults, so an omitted key keeps its default
// while an explicitly written value — including a zero — is kept and
// validated as written.
func ParsePolicy(data []byte, paths Paths, source string) (Policy, error) {
	defaults := DefaultPolicy(paths)
	policy := defaults.clone()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil {
		if errors.Is(err, io.EOF) {
			return Policy{}, &Error{Scope: source, Errors: core.FieldErrors{{
				Field:   "document",
				Message: "policy file is empty; remove it to use built-in defaults",
			}}}
		}
		return Policy{}, &Error{Scope: source, Errors: yamlFieldErrors(err)}
	}
	// A second document would silently shadow the first.
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Policy{}, &Error{Scope: source, Errors: core.FieldErrors{{
			Field:   "document",
			Message: "policy file must contain exactly one YAML document",
		}}}
	}

	policy.Source = source
	policy.FromFile = true
	errs := policy.normalize(paths, defaults)
	errs = append(errs, policy.Validate()...)
	if len(errs) > 0 {
		return Policy{}, &Error{Scope: source, Errors: errs}
	}
	return policy, nil
}

func readPolicyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPolicyBytes {
		return nil, fmt.Errorf("policy file exceeds %d bytes", MaxPolicyBytes)
	}
	return data, nil
}

var (
	unknownFieldRe = regexp.MustCompile(`^line (\d+): field (\S+) not found in type \S+$`)
	lineRe         = regexp.MustCompile(`^line (\d+): (.*)$`)
)

// yamlFieldErrors converts a yaml decode failure into field-level errors,
// keeping the line number and dropping internal Go type names.
func yamlFieldErrors(err error) core.FieldErrors {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return core.FieldErrors{fieldErrorFromMessage(err.Error())}
	}
	errs := make(core.FieldErrors, 0, len(typeErr.Errors))
	for _, msg := range typeErr.Errors {
		errs = append(errs, fieldErrorFromMessage(msg))
	}
	return errs
}

func fieldErrorFromMessage(msg string) core.FieldError {
	msg = strings.TrimSpace(msg)
	if m := unknownFieldRe.FindStringSubmatch(msg); m != nil {
		return core.FieldError{
			Field:   m[2],
			Message: fmt.Sprintf("unknown field (line %s); remove it or fix the spelling", m[1]),
		}
	}
	if m := lineRe.FindStringSubmatch(msg); m != nil {
		return core.FieldError{Field: "line " + m[1], Message: m[2]}
	}
	return core.FieldError{Field: "document", Message: msg}
}

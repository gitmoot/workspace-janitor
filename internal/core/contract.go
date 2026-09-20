// Package core defines the versioned domain contracts shared by every
// workspace-janitor component: discovered entries, evidence, protections,
// recommendations, scans, plans, actions, retention, and model usage.
//
// Types in this package are storage and transport contracts. Changing the
// meaning or JSON representation of an existing field requires bumping
// ContractVersion and adding a store migration.
package core

// ContractVersion is the version of the domain model and of the JSON
// documents produced from it. It is embedded in persisted records and in
// every JSON document the CLI emits so consumers can detect a contract change
// instead of silently misreading data.
const ContractVersion = 1

// enum is the constraint for the string-backed enumerations below.
type enum interface{ ~string }

func validEnum[T enum](v T, allowed []T) bool {
	for _, candidate := range allowed {
		if v == candidate {
			return true
		}
	}
	return false
}

func parseEnum[T enum](s string, allowed []T, name string) (T, error) {
	v := T(s)
	if validEnum(v, allowed) {
		return v, nil
	}
	var zero T
	return zero, &UnknownValueError{Kind: name, Value: s, Allowed: stringsOf(allowed)}
}

func stringsOf[T enum](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

func copyEnum[T enum](values []T) []T {
	out := make([]T, len(values))
	copy(out, values)
	return out
}

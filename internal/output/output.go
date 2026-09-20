// Package output renders command results as deterministic JSON or as
// human-readable terminal text.
//
// Deterministic means byte-identical for identical input: the JSON encoder
// never adds a timestamp, never iterates a map without sorting, and always
// emits the same field order.
package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Format selects the rendering of a command result.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Formats returns every supported output format.
func Formats() []Format { return []Format{FormatText, FormatJSON} }

// ParseFormat converts s into a Format.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unknown output format %q (allowed: text, json)", s)
	}
}

// Document is the envelope of every JSON result. The schema version lets a
// consumer detect a contract change instead of misreading new data.
type Document struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Data          any    `json:"data"`
}

// WriteJSON writes data wrapped in a versioned envelope, indented, with a
// trailing newline.
func WriteJSON(w io.Writer, kind string, data any) error {
	doc := Document{SchemaVersion: core.ContractVersion, Kind: kind, Data: data}
	encoded, err := core.MarshalIndentJSON(doc)
	if err != nil {
		return fmt.Errorf("encode %s document: %w", kind, err)
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write %s document: %w", kind, err)
	}
	return nil
}

// Field is one key/value line of terminal output.
type Field struct {
	Key   string
	Value string
}

// WriteFields renders aligned "key: value" lines.
func WriteFields(w io.Writer, fields []Field) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range fields {
		if _, err := fmt.Fprintf(tw, "%s\t%s\n", f.Key, f.Value); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// WriteTable renders a header row and aligned columns. Rows are written in
// the order given; callers sort before rendering.
func WriteTable(w io.Writer, headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(headers) > 0 {
		if _, err := fmt.Fprintln(tw, strings.Join(headers, "\t")); err != nil {
			return err
		}
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// WriteHeading writes a section heading followed by a blank line separator.
func WriteHeading(w io.Writer, title string) error {
	_, err := fmt.Fprintf(w, "%s\n", title)
	return err
}

// HumanBytes renders a byte count with a binary unit suffix.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

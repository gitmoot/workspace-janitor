package jev

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Request is the body of POST /v1/systemone, per the TypeSafe API
// reference: a state, a model, and a map of typed questions.
type Request struct {
	State     State               `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]Question `json:"questions"`
}

// State is what every question is evaluated against. Entries are packed
// into one state so a request can carry several of them.
type State struct {
	Task    string       `json:"task"`
	Entries []Projection `json:"entries"`
}

// Question is a typed question: noul, choice, or score.
type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

// Encode renders a request exactly as it is sent. Dry-run and debug show
// these same bytes. HTML escaping is off so "<root>" reads as written.
func Encode(request Request) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(request); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Response is the body of a successful evaluation.
type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   Usage             `json:"usage"`
}

// Answer is one typed answer. Fields are pointers where zero is a
// legitimate value, so a missing field is distinguishable from a zero.
type Answer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
}

// Usage is the token accounting the API reports.
type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

// task frames every request. It names the job and, importantly, what the
// answers are for: the model is told its output is advisory.
const task = "Classify workspace directories on a developer machine for a cleanup tool. " +
	"Each entry is sanitized metadata only: no file contents are available. " +
	"Answers are advisory; a deterministic safety engine makes every final decision."

// classCriteria are the built-in artifact classes a model may choose.
var classCriteria = map[string]string{
	string(core.ClassPrimaryProject):    "A primary source checkout or project someone actively maintains",
	string(core.ClassTaskWorktree):      "A temporary worktree or checkout made for one task or review",
	string(core.ClassGeneratedArtifact): "Build output or installed dependencies that can be regenerated",
	string(core.ClassCache):             "A tool cache that can be rebuilt automatically",
	string(core.ClassBackup):            "An archive or backup copy of something else",
	string(core.ClassOperationalTool):   "The operator's own tooling, scripts, or configuration",
	string(core.ClassEvidence):          "Records, logs, receipts, or incident material kept deliberately",
	string(core.ClassUnknown):           "Not enough information to tell",
}

// actionCriteria are the only actions a model may propose. Relocate and
// delete are deliberately absent: the model can never propose either.
var actionCriteria = map[string]string{
	string(core.ActionKeep):        "Leave it where it is; it is in use or worth keeping",
	string(core.ActionQuarantine):  "Move it aside reversibly; it looks regenerable or abandoned",
	string(core.ActionInvestigate): "A human should look before anything happens",
}

// retentionCriteria are the retention periods a model may choose.
var retentionCriteria = map[string]string{
	string(core.RetentionNone):      "Not applicable, or delete as soon as retention allows",
	string(core.Retention7Days):     "Keep a quarantined copy for a week",
	string(core.Retention30Days):    "Keep a quarantined copy for a month",
	string(core.Retention90Days):    "Keep a quarantined copy for three months",
	string(core.RetentionPermanent): "Never delete a quarantined copy automatically",
}

// Question keys for one entry. The API does not show keys to the model, so
// they only need to be unique and stable.
func classKey(ref string) string     { return ref + "_class" }
func actionKey(ref string) string    { return ref + "_action" }
func unsafeKey(ref string) string    { return ref + "_unsafe" }
func retentionKey(ref string) string { return ref + "_retention" }

// entryInstructions points a question at one entry by reference, using the
// structured-instructions form the API documents.
func entryInstructions(ref, question string) map[string]string {
	return map[string]string{
		"entry":    ref,
		"question": question,
	}
}

// questionsFor builds the four typed questions for one entry.
func questionsFor(ref string) map[string]Question {
	return map[string]Question{
		classKey(ref): {
			Type: "choice",
			Instructions: entryInstructions(ref,
				"What kind of artifact is the item in `entries` whose `ref` equals `entry`?"),
			Criteria: classCriteria,
		},
		actionKey(ref): {
			Type: "choice",
			Instructions: entryInstructions(ref,
				"What should a cautious cleanup tool do with the item in `entries` whose `ref` equals `entry`?"),
			Criteria: actionCriteria,
		},
		unsafeKey(ref): {
			Type: "noul",
			Instructions: entryInstructions(ref,
				"Would removing the item in `entries` whose `ref` equals `entry` risk losing work or breaking something?"),
			Criteria: map[string]string{
				"true":  "Removing it could lose unrecoverable work or break a running system",
				"false": "It is safe to move aside and regenerate if needed",
			},
		},
		retentionKey(ref): {
			Type: "choice",
			Instructions: entryInstructions(ref,
				"If the item in `entries` whose `ref` equals `entry` were quarantined, how long should the copy be kept?"),
			Criteria: retentionCriteria,
		},
	}
}

// Build assembles one request for a batch of projections.
func Build(model string, batch []Projection) Request {
	questions := make(map[string]Question, len(batch)*4)
	for _, projection := range batch {
		for key, question := range questionsFor(projection.Ref) {
			questions[key] = question
		}
	}
	return Request{
		State:     State{Task: task, Entries: batch},
		Model:     model,
		Questions: questions,
	}
}

// Documented limits, per request: 64k tokens overall, and 32k for the
// state plus the longest single question. The overall ceiling here keeps a
// margin below 64k because token counts are estimated, not measured.
const requestTokenLimit = 56000

// estimateTokens over-estimates tokens from encoded size. Three bytes per
// token is deliberately pessimistic: an under-estimate would produce a
// request the API rejects, while an over-estimate only costs batch size.
func estimateTokens(v any) int {
	encoded, err := json.Marshal(v)
	if err != nil {
		return requestTokenLimit + 1
	}
	return (len(encoded) + 2) / 3
}

// Batches packs projections into requests that fit the context limits.
//
// Projections that cannot fit even alone are returned separately: they
// cannot be sent, so they are never classified by the model.
func Batches(model string, projections []Projection, maxBatch, maxStateTokens int) (batches [][]Projection, oversized []Projection) {
	longestQuestion := 0
	for _, question := range questionsFor("e0000") {
		if tokens := estimateTokens(question); tokens > longestQuestion {
			longestQuestion = tokens
		}
	}

	var current []Projection
	flush := func() {
		if len(current) > 0 {
			batches = append(batches, current)
			current = nil
		}
	}
	for _, projection := range projections {
		alone := State{Task: task, Entries: []Projection{projection}}
		if estimateTokens(alone)+longestQuestion > maxStateTokens ||
			estimateTokens(Build(model, []Projection{projection})) > requestTokenLimit {
			oversized = append(oversized, projection)
			continue
		}
		candidate := append(append([]Projection(nil), current...), projection)
		state := State{Task: task, Entries: candidate}
		fits := len(candidate) <= maxBatch &&
			estimateTokens(state)+longestQuestion <= maxStateTokens &&
			estimateTokens(Build(model, candidate)) <= requestTokenLimit
		if !fits {
			flush()
			candidate = []Projection{projection}
		}
		current = candidate
	}
	flush()
	return batches, oversized
}

// Thresholds decides when an answer is firm enough to act on.
type Thresholds struct {
	MinConfidence float64
	MaxUnsafe     float64
}

// MapAnswers turns one entry's typed answers into a recommendation.
//
// Anything short of a complete, well-formed, confident answer becomes
// investigate with the reason stated: a model that is unsure, or whose
// answer cannot be parsed, must not move a decision anywhere.
func MapAnswers(ref string, response Response, thresholds Thresholds, decidedAt time.Time) core.Recommendation {
	recommendation, _ := mapAnswers(ref, response, thresholds, decidedAt)
	return recommendation
}

// mapAnswers distinguishes valid uncertainty from malformed answers.
// Only valid answers are cached, so a transient malformed reply is retried.
func mapAnswers(ref string, response Response, thresholds Thresholds, decidedAt time.Time) (core.Recommendation, bool) {
	investigate := func(class core.ArtifactClass, confidence float64, reason string) core.Recommendation {
		return core.Recommendation{
			Action:     core.ActionInvestigate,
			Class:      class,
			Retention:  core.RetentionNone,
			Confidence: clamp01(confidence),
			Origin:     core.OriginModel,
			Reasons:    []string{fmt.Sprintf("%s (model %s)", reason, response.Model)},
			DecidedAt:  decidedAt,
		}
	}

	class, classConfidence, err := choiceAnswer(response.Answers[classKey(ref)], classCriteria)
	if err != nil {
		return investigate(core.ClassUnknown, 0, "class answer unusable: "+err.Error()), false
	}
	labelled := core.ArtifactClass(class)
	if classConfidence < thresholds.MinConfidence {
		labelled = core.ClassUnknown
	}
	action, actionConfidence, err := choiceAnswer(response.Answers[actionKey(ref)], actionCriteria)
	if err != nil {
		return investigate(labelled, 0, "action answer unusable: "+err.Error()), false
	}
	retention, _, err := choiceAnswer(response.Answers[retentionKey(ref)], retentionCriteria)
	if err != nil {
		return investigate(labelled, 0, "retention answer unusable: "+err.Error()), false
	}
	unsafe, err := noulAnswer(response.Answers[unsafeKey(ref)])
	if err != nil {
		return investigate(labelled, 0, "unsafe-probability answer unusable: "+err.Error()), false
	}

	confidence := classConfidence
	if actionConfidence < confidence {
		confidence = actionConfidence
	}
	switch {
	case confidence < thresholds.MinConfidence:
		return investigate(labelled, confidence,
			fmt.Sprintf("confidence %.2f is below the %.2f threshold", confidence, thresholds.MinConfidence)), true
	case unsafe > thresholds.MaxUnsafe:
		return investigate(labelled, confidence,
			fmt.Sprintf("unsafe-to-remove probability %.2f exceeds the %.2f threshold", unsafe, thresholds.MaxUnsafe)), true
	}

	recommendation := core.Recommendation{
		Action:     core.ActionKind(action),
		Class:      labelled,
		Retention:  core.RetentionNone,
		Confidence: clamp01(confidence),
		Origin:     core.OriginModel,
		Reasons: []string{fmt.Sprintf("model %s: %s, %s (confidence %.2f, unsafe %.2f)",
			response.Model, class, action, confidence, unsafe)},
		DecidedAt: decidedAt,
	}
	if recommendation.Action == core.ActionQuarantine {
		recommendation.Retention = core.Retention(retention)
	}
	return recommendation, true
}

// choiceAnswer validates a choice answer against the options that were
// offered. An option the question never listed is a malformed answer.
func choiceAnswer(answer Answer, options map[string]string) (string, float64, error) {
	if answer.Type == "" {
		return "", 0, fmt.Errorf("missing")
	}
	if answer.Type != "choice" {
		return "", 0, fmt.Errorf("expected a choice answer, got %q", answer.Type)
	}
	if _, ok := options[answer.Choice]; !ok {
		return "", 0, fmt.Errorf("choice %q was not one of the options offered (%s)", answer.Choice, optionList(options))
	}
	if answer.Confidence == nil {
		return "", 0, fmt.Errorf("no confidence reported")
	}
	if *answer.Confidence < 0 || *answer.Confidence > 1 {
		return "", 0, fmt.Errorf("confidence %v is outside [0, 1]", *answer.Confidence)
	}
	return answer.Choice, *answer.Confidence, nil
}

func noulAnswer(answer Answer) (float64, error) {
	if answer.Type == "" {
		return 0, fmt.Errorf("missing")
	}
	if answer.Type != "noul" {
		return 0, fmt.Errorf("expected a noul answer, got %q", answer.Type)
	}
	if answer.Noul == nil {
		return 0, fmt.Errorf("no probability reported")
	}
	if *answer.Noul < 0 || *answer.Noul > 1 {
		return 0, fmt.Errorf("probability %v is outside [0, 1]", *answer.Noul)
	}
	return *answer.Noul, nil
}

func optionList(options map[string]string) string {
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

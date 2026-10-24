package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/output"
)

func inventoryInt(value *int64) string {
	if value == nil {
		return "unknown"
	}
	return strconv.FormatInt(*value, 10)
}

func inventoryUint(value *uint64) string {
	if value == nil {
		return "unknown"
	}
	return strconv.FormatUint(*value, 10)
}

func appendInventoryFields(fields []output.Field, report *inventoryReport) []output.Field {
	if report == nil {
		return fields
	}
	growth := &report.Growth
	observed := "unknown"
	if growth.FinishedAt != nil {
		observed = growth.FinishedAt.Format(time.RFC3339Nano)
	}
	fields = append(fields, output.Field{Key: "inventory growth:", Value: fmt.Sprintf("%s as_of=%s scan=%s previous=%s stale=%t comparable=%d unknown=%d omitted=%d", growth.Status, observed, growth.ScanID, growth.PreviousScanID, growth.Stale, growth.ComparableEntries, growth.UnknownEntries, growth.OmittedChanges)})
	for i := range growth.Changes {
		change := &growth.Changes[i]
		value := "unknown: " + change.Reason
		if change.Change != nil {
			value = fmt.Sprintf("%+d apparent bytes", *change.Change)
		}
		fields = append(fields, output.Field{Key: change.Path + ":", Value: value + "; owner=" + change.Owner})
	}
	for i := range report.Budgets {
		budget := &report.Budgets[i]
		fields = append(fields, output.Field{Key: "store " + budget.Path + ":", Value: fmt.Sprintf("owner=%s observed_apparent=%s logical_threshold=%s allocated_prune_cap=%s export_file_cap=%s retention=%s; %s", budget.Owner, inventoryInt(budget.ApparentBytes), inventoryInt(budget.LogicalThreshold), inventoryInt(budget.AllocatedPruneCap), inventoryInt(budget.ExportFileCap), budget.Retention, strings.Join(budget.Reasons, "; "))})
	}
	shown := min(len(report.Activities), 16)
	fields = append(fields, output.Field{Key: "activity history:", Value: fmt.Sprintf("showing %d of %d retained; reporting bound=%d; authoritative audit receipts are separate", shown, len(report.Activities), report.ActivityHistoryLimit)})
	for i := range shown {
		activity := &report.Activities[i]
		fields = append(fields, output.Field{Key: activity.Kind + " " + activity.ID + ":", Value: fmt.Sprintf("state=%s fresh=%d replayed=%d estimated=%s actual_reclaimed=%s store_reduction=%s available=%s -> %s change=%s stop=%s; %s", activity.State, activity.Completed, activity.Replayed, inventoryInt(activity.EstimatedReclaimBytes), inventoryInt(activity.ActualReclaimedBytes), inventoryInt(activity.StoreRemovedBytes), inventoryUint(activity.AvailableBeforeBytes), inventoryUint(activity.AvailableAfterBytes), inventoryInt(activity.AvailableChangeBytes), activity.StopReason, strings.Join(activity.Errors, "; "))})
		for _, skipped := range activity.Skipped {
			fields = append(fields, output.Field{Key: "skipped " + skipped.Path + ":", Value: "owner=" + skipped.Owner + "; " + skipped.Reason})
		}
		if activity.SkippedOmitted > 0 {
			fields = append(fields, output.Field{Key: "additional skipped:", Value: strconv.Itoa(activity.SkippedOmitted)})
		}
	}
	for _, decision := range report.Unresolved {
		fields = append(fields, output.Field{Key: "decision needed:", Value: decision})
	}
	fields = append(fields, output.Field{Key: "measurement limits:", Value: growth.Limitations + " Available-space deltas include concurrent writers and delayed frees; they are not attributable recovery. Null is unknown. Starting activities lack a confirmed outcome; inspect authoritative receipts before retrying."})
	return fields
}

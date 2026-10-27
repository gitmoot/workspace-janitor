package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func fixtureReply(path, kind string, at time.Time) ReportReply {
	return ReportReply{Path: path, Reply: kind, Role: "seat-a", Owner: "seat-a",
		NewestModifiedAt: at.Add(-30 * 24 * time.Hour), SizeBytes: 4096, Device: 1, Inode: 2, RecordedAt: at}
}

// Replies are audit records: a later reply supersedes an earlier one by
// appending, and the database itself refuses UPDATE and DELETE, so neither a
// bug nor a hand edit can rewrite or erase who released or kept what.
func TestReportRepliesAreAppendOnlyAndNewestWins(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	var first, second int64
	err := db.Write(ctx, func(tx *Tx) error {
		var err error
		if first, err = tx.RecordReportReply(ctx, fixtureReply("/srv/work/a", ReportReplyRelease, at)); err != nil {
			return err
		}
		keep := fixtureReply("/srv/work/a", ReportReplyKeep, at.Add(time.Hour))
		until := at.Add(7 * 24 * time.Hour)
		keep.Until = &until
		second, err = tx.RecordReportReply(ctx, keep)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if second <= first {
		t.Fatalf("sequences %d then %d are not increasing", first, second)
	}
	for _, statement := range []string{
		`UPDATE report_replies SET reply = 'release'`,
		`UPDATE report_replies SET document = '{}'`,
		`DELETE FROM report_replies`,
	} {
		err := db.Write(ctx, func(tx *Tx) error {
			_, err := tx.tx.ExecContext(ctx, statement)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s was not refused as immutable: %v", statement, err)
		}
	}
	var replies []ReportReply
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		replies, err = tx.ReportReplies(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 || replies[0].Sequence != second || replies[0].Reply != ReportReplyKeep || replies[0].Until == nil {
		t.Fatalf("effective replies = %+v, want only the later keep (sequence %d)", replies, second)
	}
	read, err := ReadReportReplies(ctx, db.path)
	if err != nil || len(read) != 1 || read[0].Sequence != second {
		t.Fatalf("read-only replies = %+v, %v", read, err)
	}
}

// A malformed reply never reaches the table: a release that claims an until
// date, an unknown reply kind, or a reply without a snapshot.
func TestReportReplyRejectsMalformedReplies(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Now().UTC()
	until := at.Add(time.Hour)
	release := fixtureReply("/srv/work/a", ReportReplyRelease, at)
	release.Until = &until
	unknown := fixtureReply("/srv/work/a", "archive", at)
	unsnapshotted := fixtureReply("/srv/work/a", ReportReplyKeep, at)
	unsnapshotted.NewestModifiedAt = time.Time{}
	for name, reply := range map[string]ReportReply{"release with until": release, "unknown kind": unknown, "no snapshot": unsnapshotted} {
		err := db.Write(ctx, func(tx *Tx) error {
			_, err := tx.RecordReportReply(ctx, reply)
			return err
		})
		if err == nil {
			t.Errorf("%s was recorded", name)
		}
	}
}

// The category receipts that released report items are archived under share
// the same guarantee: receipts and withdrawals can be appended, never edited
// or erased.
func TestCategoryArchiveReceiptsAndWithdrawalsAreImmutable(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.RecordCategoryArchive(ctx, CategoryArchive{
			Name: "report-release-a-000000000000", Category: "report-release", Kind: "root_scratch", Path: "/srv/work/a",
			Owner: "category:report-release", Release: "seat-a@report-reply-1", RunID: "category-run", ArchiveDirectory: "/srv/archive",
			Manifest: "/srv/archive/report-release-a-000000000000.manifest.json", ManifestSHA256: strings.Repeat("a", 64),
			ContentBytes: 1, Members: 1, CreatedAt: at, RecordedAt: at,
		}); err != nil {
			return err
		}
		return tx.WithdrawCategoryArchive(ctx, "report-release-a-000000000000", "restored", at)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE category_archives SET path = '/srv/work/b'`,
		`DELETE FROM category_archives`,
		`UPDATE category_archive_withdrawals SET reason = 'edited'`,
		`DELETE FROM category_archive_withdrawals`,
	} {
		err := db.Write(ctx, func(tx *Tx) error {
			_, err := tx.tx.ExecContext(ctx, statement)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s was not refused as immutable: %v", statement, err)
		}
	}
}

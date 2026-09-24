//go:build linux

package cli

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/jev"
)

func TestDailyAdvisoryReservationBeforeMidnightCannotSendAfter(t *testing.T) {
	server, calls := advisoryFakeServer(t, http.StatusOK)
	day := "2026-09-24"
	clock := time.Date(2026, 9, 24, 23, 59, 59, 0, time.UTC)
	reservations := 0
	client := &jev.Client{
		Endpoint: server.URL + "/api/v1/systemone", APIKey: "synthetic-only-key",
		HTTP: server.Client(), Timeout: time.Second, MaxRetries: 2,
		SendDeadline: time.Now().Add(time.Minute),
		BeforeAttempt: func(context.Context, jev.Request, []byte) error {
			reservations++ // Simulate a committed old-day reservation and a paused process.
			clock = clock.Add(2 * time.Second)
			return nil
		},
		BeforeSend: func(context.Context) error { return advisorySendDay(day, clock) },
	}
	exchange, err := client.Evaluate(context.Background(), jev.Build("typesafe/jev-1.13", nil))
	var apiErr *jev.APIError
	if !errors.As(err, &apiErr) || !apiErr.Fatal || exchange.Attempts != 1 || reservations != 1 || calls.Load() != 0 {
		t.Fatalf("midnight reservation sent or retried: err=%v exchange=%+v reservations=%d calls=%d", err, exchange, reservations, calls.Load())
	}
}

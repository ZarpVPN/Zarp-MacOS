package route

import (
	"context"
	"errors"
	"testing"
	"time"
)

type cancelledInspection struct{ entered, joined chan struct{} }

func (r *cancelledInspection) Run(string, ...string) (string, error) {
	panic("account inspection lost its request context")
}
func (r *cancelledInspection) RunContext(ctx context.Context, _ string, _ ...string) (string, error) {
	close(r.entered)
	<-ctx.Done()
	close(r.joined)
	return "", ctx.Err()
}
func TestAccountRouteInspectionCancelsAndJoinsItsReadOnlyCommand(t *testing.T) {
	runner := &cancelledInspection{make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := New(runner).InspectPhysical(ctx, false); done <- err }()
	<-runner.entered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled inspection accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("inspection did not stop")
	}
	select {
	case <-runner.joined:
	default:
		t.Fatal("inspection returned before command joined")
	}
	_, err := (ExecRunner{}).RunContext(ctx, "/does-not-exist")
	if !errors.Is(err, context.Canceled) {
		t.Fatal("command runner ignored parent cancellation", err)
	}
}

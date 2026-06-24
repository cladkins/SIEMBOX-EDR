package osquery

import (
	"encoding/json"
	"testing"
)

func TestParseDifferentialLine(t *testing.T) {
	line := `{"name":"pack/siembox/processes","action":"added","unixTime":1700000000,"columns":{"pid":"42","name":"sh","path":"/tmp/sh"}}`
	records, err := parseResultLine([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	if r.Query != "processes" { // prefix stripped
		t.Errorf("query = %q, want processes", r.Query)
	}
	if r.Action != "added" {
		t.Errorf("action = %q", r.Action)
	}
	if r.Columns["path"] != "/tmp/sh" {
		t.Errorf("columns = %v", r.Columns)
	}
	if r.Timestamp.IsZero() {
		t.Error("timestamp not set")
	}
}

func TestParseSnapshotLine(t *testing.T) {
	line := `{"name":"listening_ports","action":"snapshot","unixTime":1700000000,"snapshot":[{"port":"22"},{"port":"80"}]}`
	records, err := parseResultLine([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Action != "snapshot" || records[1].Columns["port"] != "80" {
		t.Errorf("unexpected snapshot records: %+v", records)
	}
}

func TestParseGarbageLine(t *testing.T) {
	if _, err := parseResultLine([]byte("not json")); err == nil {
		t.Error("expected error on garbage line")
	}
}

func TestBuildConfig(t *testing.T) {
	cfg, err := buildConfig(DefaultQueries())
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	var parsed struct {
		Options  map[string]any `json:"options"`
		Schedule map[string]struct {
			Query    string `json:"query"`
			Interval int    `json:"interval"`
			Snapshot bool   `json:"snapshot"`
		} `json:"schedule"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatalf("config is not valid json: %v", err)
	}
	q, ok := parsed.Schedule["processes"]
	if !ok {
		t.Fatal("processes query missing from schedule")
	}
	if q.Interval != 60 || q.Snapshot {
		t.Errorf("processes schedule = %+v", q)
	}
	if q.Query == "" {
		t.Error("processes query SQL empty")
	}
}

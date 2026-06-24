// Package telemetry defines the host-telemetry abstraction consumed by the
// detection engine. A Source produces Records (rows of host state, e.g. from
// osquery scheduled queries) which the detection engine evaluates against
// Sigma rules. Decoupling the engine from osquery via this interface keeps the
// engine unit-testable with a fake source.
package telemetry

import (
	"context"
	"time"
)

// Record is a single row of host telemetry.
type Record struct {
	// Query is the logical source name, e.g. "processes" or "listening_ports".
	Query string
	// Action is the differential action for scheduled queries: "added",
	// "removed", or "snapshot". Empty for sources that don't differentiate.
	Action string
	// Columns are the row's fields as returned by the source (osquery returns
	// all values as strings).
	Columns map[string]string
	// Timestamp is when the row was observed.
	Timestamp time.Time
}

// Source produces telemetry records to out until ctx is cancelled. Start blocks
// until ctx is done or an unrecoverable error occurs.
type Source interface {
	Start(ctx context.Context, out chan<- Record) error
}

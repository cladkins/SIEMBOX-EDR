package osquery

// DefaultQueries is a small, cross-platform scheduled query pack. Column names
// here are the field names the bundled Sigma rules match against. Queries run
// in differential mode so each tick yields only newly-added rows.
func DefaultQueries() []Query {
	return []Query{
		{
			Name:     "processes",
			SQL:      "SELECT pid, name, path, cmdline, parent, uid FROM processes;",
			Interval: 60,
		},
		{
			Name:     "listening_ports",
			SQL:      "SELECT pid, port, protocol, address FROM listening_ports;",
			Interval: 60,
		},
		{
			Name:     "logged_in_users",
			SQL:      "SELECT user, tty, host, time, pid FROM logged_in_users;",
			Interval: 60,
		},
	}
}

//go:build !linux

package ecoutil

// limitMemory is a no-op off Linux (the gate runs on Linux runners; macOS
// does not enforce RLIMIT_AS). ChildMain still sets a soft Go memory
// limit, and the parent's timeout still applies.
func limitMemory(uint64) error { return nil }

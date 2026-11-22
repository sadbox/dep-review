package ecoutil

import "syscall"

// limitMemory caps this process's address space; allocations past it
// fail, and the Go runtime exits.
func limitMemory(n uint64) error {
	return syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: n, Max: n})
}

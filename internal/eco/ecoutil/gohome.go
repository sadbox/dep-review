package ecoutil

import (
	"os"
	"path/filepath"
)

// GoHome prepares home as the HOME of a go command the gate runs, with
// Go telemetry off. The toolchain reads the mode from
// os.UserConfigDir()/go/telemetry/mode; for a HOME with XDG_CONFIG_HOME
// unset, as in every environment the gate writes, that is $HOME/.config
// on Linux and $HOME/Library/Application Support on macOS: both are
// written. Without the file the mode is "local", and the go command
// starts a telemetry sidecar process that writes counters under home
// after the command itself has returned. "off" is what `go telemetry off`
// writes (golang.org/x/telemetry internal/telemetry.Dir.SetMode,
// "<mode> <date>"; the date is optional). The GOTELEMETRY variable is go
// env's report of the mode; the toolchain does not read it from the
// environment.
func GoHome(home string) error {
	for _, cfg := range []string{".config", filepath.Join("Library", "Application Support")} {
		dir := filepath.Join(home, cfg, "go", "telemetry")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "mode"), []byte("off"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

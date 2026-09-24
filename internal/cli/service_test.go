package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceGenerationWritesOfflineUnitsWithoutInstalling(t *testing.T) {
	f := newFixture(t)
	binary := filepath.Join(f.home, "janitor-bin")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "prevention:\n  auto_expire: false\n")
	output := filepath.Join(f.home, "generated-units")
	stdout, stderr, code := f.run(t, "service", "generate", "--output", output, "--binary", binary)
	if code != ExitOK {
		t.Fatalf("generate: %s %s", stdout, stderr)
	}
	for name, needle := range map[string]string{
		"janitor-watch.service": " watch\n",
		"janitor-cycle.service": " cycle\n",
		"janitor-cycle.timer":   "OnCalendar=daily",
	} {
		data, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || !strings.Contains(string(data), needle) {
			t.Fatalf("unit %s missing executable schedule: %v %s", name, err, data)
		}
		if strings.HasSuffix(name, ".service") && !strings.Contains(string(data), "IPAddressDeny=any") {
			t.Fatalf("unit %s did not disable networking", name)
		}
	}
	advisory, err := os.ReadFile(filepath.Join(output, "janitor-advisory.service"))
	if err != nil || !strings.Contains(string(advisory), " advisory run --key-file /root/.env") ||
		!strings.Contains(string(advisory), "Environment=OPENROUTER_API_KEY=") ||
		strings.Contains(string(advisory), "EnvironmentFile=") {
		t.Fatalf("advisory unit does not read only the key at execution time: %v", err)
	}
	dropin, err := os.ReadFile(filepath.Join(output, "janitor-cycle-advisory.conf"))
	if err != nil || !strings.Contains(string(dropin), "OnSuccess=janitor-advisory.service") {
		t.Fatalf("opt-in success drop-in missing: %v", err)
	}
	offlineCycle, _ := os.ReadFile(filepath.Join(output, "janitor-cycle.service"))
	if strings.Contains(string(offlineCycle), "OnSuccess=") {
		t.Fatal("default offline cycle gained an automatic advisory trigger")
	}
	if _, err := os.Stat(filepath.Join(f.home, ".config", "systemd", "user", "janitor-watch.service")); !os.IsNotExist(err) {
		t.Fatalf("generator installed a live unit: %v", err)
	}
	if _, _, code := f.run(t, "service", "generate", "--output", output, "--binary", binary); code == ExitOK {
		t.Fatal("generator overwrote existing units")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steflokos/assess/internal/cli"
)

// The scripts of the web interface have tests of their own, in internal/server/ui/tests. They run with node, which is not needed for
// anything else, so this test is skipped where node is not installed. The scripts get the real answers of describe and export on the
// test project, so what they work out is checked against the real data. One of them signs an iteration in the way the page does. The
// signature goes to assess sign here, which shows that what the browser makes is what assess accepts.
func TestTheScriptsOfTheInterface(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed, so the scripts of the interface are not tested")
	}
	dir := twoIterations(t)
	fx := t.TempDir()
	for name, args := range map[string][]string{"describe": {"describe", "-format", "json"}, "export": {"export", dir}} {
		r := run(t, args...)
		if err := os.WriteFile(filepath.Join(fx, name+".json"), []byte(r.out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join("..", "server", "ui", "tests", "*.test.js"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no test files: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, append([]string{"--test"}, files...)...)
	cmd.Env = append(os.Environ(), "ASSESS_FIXTURES="+fx, "ASSESS_SIGN_HASH="+lastHash(t, dir))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the tests of the scripts failed:\n%s", out)
	}

	raw, err := os.ReadFile(filepath.Join(fx, "signed.json"))
	if err != nil {
		t.Fatalf("the script did not write its signature: %v", err)
	}
	var made struct{ Signature, Public string }
	if err := json.Unmarshal(raw, &made); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := cli.RunWith(strings.NewReader(made.Public), []string{"sign", "-signature", made.Signature, "-public", "-", "-by", "Jane Doe", dir}, &out, &errb); code != 0 {
		t.Fatalf("assess does not accept the signature that the page makes: exit %d\n%s%s", code, out.String(), errb.String())
	}
	pub := filepath.Join(t.TempDir(), "jane.pub")
	if err := os.WriteFile(pub, []byte(made.Public), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "verify", "-keys", pub, "-strict", dir); r.code != 0 || !strings.Contains(r.out, "signed by Jane Doe: valid") {
		t.Errorf("the signature is valid: %s%s", r.out, r.err)
	}
}

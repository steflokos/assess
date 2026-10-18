// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package yamlx_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/yamlx"
)

func node(t *testing.T, text string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Content[0]
}

func TestMessagesCarryTheirPosition(t *testing.T) {
	n := node(t, "\n\n   key: value\n").Content[1]
	if got := yamlx.Msgf(n, "wrong %s", "thing"); got != "line 3:9: wrong thing" {
		t.Errorf("%q", got)
	}
}

func TestErrfIsATypeErrorTheDecoderCollects(t *testing.T) {
	n := node(t, "a: b\n").Content[1]
	err := yamlx.Errf(n, "no")
	var te *yaml.TypeError
	if !errors.As(err, &te) || len(te.Errors) != 1 || te.Errors[0] != "line 1:4: no" {
		t.Errorf("%v", err)
	}
	if got := yamlx.Messages(err); len(got) != 1 || got[0] != "line 1:4: no" {
		t.Errorf("%v", got)
	}
	if got := yamlx.Messages(errors.New("plain")); len(got) != 1 || got[0] != "plain" {
		t.Errorf("%v", got)
	}
	multi := &yaml.TypeError{Errors: []string{"one", "two"}}
	if got := yamlx.Messages(fmt.Errorf("wrapped: %w", multi)); len(got) != 2 {
		t.Errorf("a wrapped type error gives its messages: %v", got)
	}
}

func TestDecodeEnum(t *testing.T) {
	allowed := []string{"High", "Low"}
	got, err := yamlx.DecodeEnum(node(t, "v: High\n").Content[1], "level", allowed)
	if err != nil || got != "High" {
		t.Errorf("%q %v", got, err)
	}
	_, err = yamlx.DecodeEnum(node(t, "v: Middle\n").Content[1], "level", allowed)
	if err == nil || yamlx.Messages(err)[0] != `line 1:4: "Middle" is not a valid level. The allowed values are High, Low` {
		t.Errorf("%v", err)
	}
	_, err = yamlx.DecodeEnum(node(t, "v: [High]\n").Content[1], "level", allowed)
	if err == nil || !strings.Contains(err.Error(), "must be a single value") {
		t.Errorf("a list is not a value: %v", err)
	}
	// the match is exact: no case folding and no trimming
	for _, bad := range []string{"high", `" High"`} {
		if _, err := yamlx.DecodeEnum(node(t, "v: "+bad+"\n").Content[1], "level", allowed); err == nil {
			t.Errorf("%s must not match", bad)
		}
	}
}

func TestPreviewShortensLongLists(t *testing.T) {
	if got := yamlx.Preview([]string{"a", "b"}); got != "a, b" {
		t.Errorf("%q", got)
	}
	long := make([]string, 25)
	for i := range long {
		long[i] = fmt.Sprintf("v%d", i)
	}
	got := yamlx.Preview(long)
	if !strings.HasPrefix(got, "v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, ... (25 values") || strings.Contains(got, "v10") {
		t.Errorf("%q", got)
	}
}

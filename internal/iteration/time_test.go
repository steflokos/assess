// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iteration_test

import (
	"testing"
	"time"

	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/model"
)

func TestShowWritesTheDateAndTimeForAPerson(t *testing.T) {
	cases := map[string]string{
		"2026-10-18T14:32:07+02:00": "2026-10-18 14:32:07+02:00",
		"2026-10-18T09:30:00Z":      "2026-10-18 09:30:00Z",
		"2026-10-18T09:30:00.5Z":    "2026-10-18 09:30:00.5Z",
		"2026-10-18":                "2026-10-18", // not a date and time, so it stays as it was written
		"yesterday":                 "yesterday",
		"":                          "",
	}
	for in, want := range cases {
		if got := iteration.Show(in); got != want {
			t.Errorf("Show(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNowIsADateAndTimeToTheSecond(t *testing.T) {
	before := time.Now().Add(-time.Second)
	s := iteration.Now()
	got, err := time.Parse(model.TimeLayout, s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	if got.Nanosecond() != 0 {
		t.Errorf("to the second: %q", s)
	}
	if got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Errorf("%v is not now", got)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iteration

import (
	"time"

	"github.com/steflokos/assess/internal/model"
)

// Now is the current time in the form an iteration writes it, to the second and with the offset of the local time zone.
func Now() string { return time.Now().Truncate(time.Second).Format(model.TimeLayout) }

// Show writes the date and time of an iteration for a person: "2026-10-18 14:32:07+02:00". Text that is not a date and
// time stays as it is.
func Show(s string) string {
	if _, err := time.Parse(model.TimeLayout, s); err != nil {
		return s
	}
	return s[:10] + " " + s[11:]
}

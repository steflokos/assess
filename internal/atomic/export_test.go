// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package atomic

import "errors"

// FailSwap makes the swaps with the given numbers fail, counting from 1 in the order they are tried, and lets the others
// through. It gives back the function that puts the real swap back. A file cannot be made to refuse a rename the same way on every
// system, so the tests say which swap fails.
func FailSwap(numbers ...int) (restore func()) {
	real := replace
	calls := 0
	replace = func(from, to string) error {
		calls++
		for _, n := range numbers {
			if n == calls {
				return errors.New("refused for the test")
			}
		}
		return real(from, to)
	}
	return func() { replace = real }
}

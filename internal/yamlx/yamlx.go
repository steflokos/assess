// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package yamlx holds the small helpers shared by every type that decodes
// itself from YAML: positioned errors and enum validation.
package yamlx

import (
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Msgf formats a message prefixed with the node position ("line L:C: ...").
// internal/load parses this prefix back into a file:line:col diagnostic.
func Msgf(n *yaml.Node, format string, args ...any) string {
	return fmt.Sprintf("line %d:%d: %s", n.Line, n.Column, fmt.Sprintf(format, args...))
}

// Errf returns an error that the YAML decoder collects as a positioned type
// error instead of aborting the whole decode.
func Errf(n *yaml.Node, format string, args ...any) error {
	return &yaml.TypeError{Errors: []string{Msgf(n, format, args...)}}
}

// Messages returns the individual messages of a decode error.
func Messages(err error) []string {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return te.Errors
	}
	return []string{err.Error()}
}

// DecodeEnum reads a scalar node and checks it against the allowed values.
// typeName is used in the message ("impact level", "stakeholder", ...).
func DecodeEnum(n *yaml.Node, typeName string, allowed []string) (string, error) {
	if n.Kind != yaml.ScalarNode {
		return "", Errf(n, "%s must be a single value, one of: %s", typeName, Preview(allowed))
	}
	for _, a := range allowed {
		if n.Value == a {
			return a, nil
		}
	}
	return "", Errf(n, "%q is not a valid %s. The allowed values are %s", n.Value, typeName, Preview(allowed))
}

// Preview renders at most ten values for an error message.
func Preview(values []string) string {
	const max = 10
	if len(values) <= max {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:max], ", ") + fmt.Sprintf(", ... (%d values, all listed in schema.yaml)", len(values))
}

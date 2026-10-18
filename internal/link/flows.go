// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package link

import (
	"fmt"
	"slices"
	"strings"
)

// CodeFlowChannel is the warning for a flow that sends over a channel its steps are not connected to.
const CodeFlowChannel = "flow-channel"

// flows checks the transfers that the function flows describe (model.Hops): the step that sends is
// at one end of the channel it sends over, the next step is at another end and the two ends are
// not the same. The direction is read from the order of the steps, so these are the only
// facts to keep consistent.
func (c *checker) flows() {
	for _, h := range c.ws.Hops() {
		ch := c.channels[h.Channel]
		if ch == nil || len(ch.Between) == 0 {
			continue // not a channel, or a channel already reported
		}
		ends := strings.Join(ch.Between, ", ")
		sendAt := c.ix.At(h.Function, fmt.Sprintf("flow[%d].at", h.Step-1))
		switch {
		case len(h.From) > 0 && len(h.FromEnds) == 0:
			c.diags.Warnf(CodeFlowChannel, sendAt,
				"step %d of %s is at %s, which is not connected to %s, the channel it sends over (the channel connects %s). Put the step at one of them, or name the channel it really uses",
				h.Step, h.Function, strings.Join(h.From, ", "), h.Channel, ends)
		case len(h.To) > 0 && len(h.ToEnds) == 0:
			c.diags.Warnf(CodeFlowChannel, c.ix.At(h.Function, fmt.Sprintf("flow[%d].at", h.Step)),
				"step %d of %s is at %s, which is not connected to %s, the channel step %d sends over (the channel connects %s). The next step is where it is received, so put it at one of them",
				h.Step+1, h.Function, strings.Join(h.To, ", "), h.Channel, h.Step, ends)
		case len(h.FromEnds) > 0 && len(h.ToEnds) > 0 && slices.Equal(h.FromEnds, h.ToEnds) && len(h.FromEnds) == 1:
			c.diags.Warnf(CodeFlowChannel, sendAt,
				"step %d of %s sends over %s and step %d is at the same end of it (%s). A transfer goes between two ends, so put the sending step at the sender and the next step at the receiver",
				h.Step, h.Function, h.Channel, h.Step+1, h.FromEnds[0])
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

// Hop is one transfer that the flow of a function describes: a step sends what it handles over a channel and the next
// step is at the receiver. Nothing is written for the direction. It is read from the order of the steps, so a fact is
// stated once.
type Hop struct {
	Function string   `json:"function"`
	Step     int      `json:"step"`    // the number (from 1) of the step that sends
	Channel  string   `json:"channel"` // the channel it is sent over
	Data     []string `json:"data"`    // the data of the sending step
	From     []string `json:"from"`    // where the sending step is (its at)
	To       []string `json:"to"`      // where the next step is, the receiver. Empty for the last step of a flow and for a step that names several channels
	// FromEnds and ToEnds are the ends of the channel that From and To are connected to. They are
	// empty when the channel does not exist or nothing named is connected to it.
	FromEnds []string `json:"fromEnds"`
	ToEnds   []string `json:"toEnds"`
}

// Hops lists the transfers of every function flow, in the order of the functions and their steps.
// A step that names several channels gives one hop for each.
func (w *Workspace) Hops() []Hop {
	channels := map[string]*Channel{}
	for i := range w.Channels {
		channels[w.Channels[i].ID] = &w.Channels[i]
	}
	parent := map[string]string{}
	for _, e := range w.Elements() {
		parent[e.Base().ID] = e.Base().Parent
	}
	var out []Hop
	for i := range w.Functions {
		f := &w.Functions[i]
		if f.Incomplete {
			continue
		}
		for n, st := range f.Flow {
			var next []string
			if n+1 < len(f.Flow) && len(st.Over) == 1 { // over several channels there is no one receiver
				next = f.Flow[n+1].At
			}
			for _, ch := range st.Over {
				h := Hop{Function: f.ID, Step: n + 1, Channel: ch, Data: st.Data, From: st.At, To: next}
				if c := channels[ch]; c != nil {
					h.FromEnds = connectedEnds(parent, c, st.At)
					h.ToEnds = connectedEnds(parent, c, next)
				}
				out = append(out, h)
			}
		}
	}
	return out
}

// connectedEnds returns the ends of a channel that some element of at is connected to: the end
// itself, an end inside it (the element is a component and the end one of its interfaces), or the
// component an end is inside of (the element is an interface of a component the channel ends at).
func connectedEnds(parent map[string]string, c *Channel, at []string) []string {
	var out []string
	for _, end := range c.Between {
		for _, x := range at {
			if x == end || inside(parent, x, end) || inside(parent, end, x) {
				out = append(out, end)
				break
			}
		}
	}
	return out
}

// inside reports whether id sits somewhere inside the element outer.
func inside(parent map[string]string, id, outer string) bool {
	for seen := 0; seen < len(parent)+1; seen++ {
		id = parent[id]
		if id == "" {
			return false
		}
		if id == outer {
			return true
		}
	}
	return false
}

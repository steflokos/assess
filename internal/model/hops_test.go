// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model_test

import (
	"reflect"
	"testing"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/testproject"
)

func hopsOf(t *testing.T, edits ...[3]string) []model.Hop {
	t.Helper()
	dir := testproject.Copy(t)
	for _, e := range edits {
		testproject.Replace(t, dir, e[0], e[1], e[2])
	}
	res := load.Load(dir)
	if res.Workspace == nil {
		t.Fatal(res.Diags)
	}
	return res.Workspace.Hops()
}

// The function of the test project asks, answers and installs. Only the first two steps send something.
func TestHopsFollowTheFlow(t *testing.T) {
	hops := hopsOf(t)
	want := []model.Hop{
		{Function: "update", Step: 1, Channel: "service-link", From: []string{"gateway"}, To: []string{"api-interface"},
			FromEnds: []string{"gateway"}, ToEnds: []string{"api-interface"}},
		{Function: "update", Step: 2, Channel: "service-link", Data: []string{"update-package"}, From: []string{"api-interface"}, To: []string{"gateway"},
			FromEnds: []string{"api-interface"}, ToEnds: []string{"gateway"}},
	}
	if !reflect.DeepEqual(hops, want) {
		t.Errorf("got %+v\nwant %+v", hops, want)
	}
}

// A step can sit at a component while the channel ends at one of its interfaces, or the other way round.
func TestHopsFindTheEndInsideOrAround(t *testing.T) {
	hops := hopsOf(t, [3]string{"item/channels.yaml", "between: [gateway, api-interface]", "between: [gateway, backend]"})
	if got := hops[0].ToEnds; !reflect.DeepEqual(got, []string{"backend"}) {
		t.Errorf("the interface is inside the backend, which the channel ends at: %v", got)
	}
	hops = hopsOf(t, [3]string{"item/channels.yaml", "between: [gateway, api-interface]", "between: [debug-port, api-interface]"})
	if got := hops[0].FromEnds; !reflect.DeepEqual(got, []string{"debug-port"}) {
		t.Errorf("the gateway holds the debug port, which the channel ends at: %v", got)
	}
}

func TestAStepOverSeveralChannelsHasNoOneReceiver(t *testing.T) {
	hops := hopsOf(t,
		[3]string{"item/channels.yaml", "between: [gateway, api-interface]\n", "between: [gateway, api-interface]\n\nchannel second-link:\n  name: Second link\n  between: [gateway, api-interface]\n"},
		[3]string{"item/functions.yaml", "      over: service-link\n    - step: The backend", "      over: [service-link, second-link]\n    - step: The backend"},
	)
	var first []model.Hop
	for _, h := range hops {
		if h.Step == 1 {
			first = append(first, h)
		}
	}
	if len(first) != 2 {
		t.Fatalf("one hop for each channel, got %d", len(first))
	}
	for _, h := range first {
		if len(h.To) != 0 {
			t.Errorf("with two channels there is no one receiver: %+v", h)
		}
	}
}

func TestAHopOverAChannelThatDoesNotExistHasNoEnds(t *testing.T) {
	hops := hopsOf(t, [3]string{"item/functions.yaml", "over: service-link\n    - step: The backend", "over: nowhere\n    - step: The backend"})
	if h := hops[0]; h.Channel != "nowhere" || len(h.FromEnds) != 0 || len(h.ToEnds) != 0 {
		t.Errorf("%+v", h)
	}
}

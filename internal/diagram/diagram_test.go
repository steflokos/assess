// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package diagram_test

import (
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/diagram"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/testproject"
)

func open(t *testing.T, files map[string]string) *model.Workspace {
	t.Helper()
	dir := testproject.Copy(t)
	for rel, text := range files {
		testproject.Write(t, dir, rel, text)
	}
	res := load.Load(dir)
	if res.Workspace == nil {
		t.Fatal(res.Diags)
	}
	return res.Workspace
}

func wellFormed(t *testing.T, svg []byte) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(string(svg)))
	for {
		if _, err := dec.Token(); err == io.EOF {
			return
		} else if err != nil {
			t.Fatalf("not well formed: %v", err)
		}
	}
}

var viewBox = regexp.MustCompile(`viewBox="0 0 ([0-9.]+) ([0-9.]+)"`)

func size(t *testing.T, svg []byte) (w, h float64) {
	t.Helper()
	m := viewBox.FindSubmatch(svg)
	if m == nil {
		t.Fatalf("no viewBox in %.200s", svg)
	}
	w, _ = strconv.ParseFloat(string(m[1]), 64)
	h, _ = strconv.ParseFloat(string(m[2]), 64)
	return
}

func TestDiagramOfTheTestProject(t *testing.T) {
	ws := open(t, nil)
	svg := diagram.SVG(ws)
	if svg == nil {
		t.Fatal("no picture")
	}
	wellFormed(t, svg)
	text := string(svg)
	for _, want := range []string{
		"System architecture: Test gateway", "Gateway", "Backend", "api-interface", "debug-port", "update-package", "firmware-image", "device-key", "service-link",
		"Outside the item", "external interface", "internal interface", "entry point", "an asset", "not an asset", "direction of a transfer in a function flow",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the picture does not show %q", want)
		}
	}
	if w, h := size(t, svg); w < 200 || h < 200 || w > 3000 || h > 3000 {
		t.Errorf("a picture of this size: %v x %v", w, h)
	}
	if again := diagram.SVG(ws); string(again) != text {
		t.Error("the same files draw the same bytes")
	}
	if strings.Contains(text, "<script") || strings.Contains(text, "href=\"http") {
		t.Error("a picture holds no script and loads nothing")
	}
}

func TestNoComponentsNoPicture(t *testing.T) {
	ws := open(t, map[string]string{"item/architecture.yaml": "", "item/channels.yaml": "", "item/functions.yaml": ""})
	if got := diagram.SVG(ws); got != nil {
		t.Errorf("a project with no component draws nothing, got %d bytes", len(got))
	}
}

func TestTheNameOfTheItemIsText(t *testing.T) {
	ws := open(t, map[string]string{"item/item.yaml": "item x:\n  name: '<b>Bold</b> & co'\n  boundary: b\n"})
	svg := diagram.SVG(ws)
	wellFormed(t, svg)
	if strings.Contains(string(svg), "<b>") || !strings.Contains(string(svg), "&lt;b&gt;Bold&lt;/b&gt; &amp; co") {
		t.Error("the name of the item in the title is shown as text")
	}
}

func TestNamesAreText(t *testing.T) {
	evil := `<script>alert("x")</script> & "q"`
	ws := open(t, map[string]string{"item/architecture.yaml": "component backend:\n  name: '" + strings.ReplaceAll(evil, "'", "''") + "'\n\n  data update-package:\n    name: x\n\ncomponent gateway:\n  name: G\n"})
	svg := diagram.SVG(ws)
	wellFormed(t, svg)
	if strings.Contains(string(svg), "<script>") || !strings.Contains(string(svg), "&lt;script&gt;") {
		t.Error("a name is shown as text")
	}
}

// What is nested is drawn inside what holds it, and the picture grows with the architecture but not without bound.
func TestLargeArchitectures(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		t.Run(fmt.Sprint("seed-", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			var arch, channels strings.Builder
			var ends []string
			var comps []string
			var emit func(id string, depth int)
			emit = func(id string, depth int) {
				ind := strings.Repeat("  ", depth)
				fmt.Fprintf(&arch, "%scomponent %s:\n%s  name: Component %s\n", ind, id, ind, id)
				comps = append(comps, id)
				ends = append(ends, id)
				for i := 0; i < rng.Intn(3); i++ {
					iid := fmt.Sprintf("%s-if%d", id, i)
					fmt.Fprintf(&arch, "\n%s  interface %s:\n%s    name: Interface %s\n", ind, iid, ind, iid)
					if rng.Intn(2) == 0 {
						fmt.Fprintf(&arch, "%s    exposure: External\n", ind)
					}
					ends = append(ends, iid)
				}
				for i := 0; i < rng.Intn(5); i++ {
					did := fmt.Sprintf("%s-data%d", id, i)
					fmt.Fprintf(&arch, "\n%s  data %s:\n%s    name: Data %s with a name that is rather long\n", ind, did, ind, did)
				}
				if depth < 2 {
					for i := 0; i < rng.Intn(3); i++ {
						arch.WriteString("\n")
						emit(fmt.Sprintf("%s-c%d", id, i), depth+1)
					}
				}
			}
			for i := 0; i < 8; i++ {
				emit(fmt.Sprintf("top%d", i), 0)
				arch.WriteString("\n")
			}
			for i := 0; i < 40; i++ {
				a, b := ends[rng.Intn(len(ends))], ends[rng.Intn(len(ends))]
				if a == b {
					continue
				}
				fmt.Fprintf(&channels, "channel link%d:\n  name: Link %d\n  between: [%s, %s]\n\n", i, i, a, b)
			}
			ws := open(t, map[string]string{"item/architecture.yaml": arch.String(), "item/channels.yaml": channels.String(), "item/functions.yaml": ""})
			svg := diagram.SVG(ws)
			if svg == nil {
				t.Fatal("no picture")
			}
			wellFormed(t, svg)
			for _, c := range comps {
				if !strings.Contains(string(svg), "Component "+c) {
					t.Errorf("component %s is not drawn", c)
				}
			}
			if w, h := size(t, svg); w <= 0 || h <= 0 || w > 20000 || h > 20000 {
				t.Errorf("%v x %v", w, h)
			}
			if string(diagram.SVG(ws)) != string(svg) {
				t.Error("not deterministic")
			}
		})
	}
}

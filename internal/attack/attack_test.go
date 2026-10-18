// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package attack_test

import (
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"math/rand"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/testproject"
)

// open loads the test project, with some files written again, and runs the engine.
func open(t *testing.T, files map[string]string) (*model.Workspace, *engine.Report) {
	t.Helper()
	dir := testproject.Copy(t)
	for rel, text := range files {
		testproject.Write(t, dir, rel, text)
	}
	res := load.Load(dir)
	if res.Workspace == nil {
		t.Fatal(res.Diags)
	}
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Workspace, rep
}

// graphOf builds the structure of a threat scenario with the easiest paths of the calculation marked.
func graphOf(t *testing.T, ws *model.Workspace, rep *engine.Report, threat string) *attack.Graph {
	t.Helper()
	for _, r := range rep.Threats {
		if r.Threat == threat {
			var base, resid *engine.Path
			if r.Base != nil {
				base = &r.Base.Best
			}
			if r.Residual != nil {
				resid = &r.Residual.Best
			}
			g := attack.NewIndex(ws).Graph(threat, base, resid)
			if g == nil {
				t.Fatalf("no graph for %s", threat)
			}
			return g
		}
	}
	t.Fatalf("no threat scenario %s", threat)
	return nil
}

// text writes the structure as indented lines: what a node is, how it hangs under its parent, and the flags.
func text(g *attack.Graph) string {
	var b strings.Builder
	var walk func(n *attack.Node, depth int)
	walk = func(n *attack.Node, depth int) {
		label := string(n.Kind)
		if n.ID != "" {
			label += " " + n.ID
		}
		flags := ""
		for _, f := range []struct {
			on   bool
			word string
		}{{n.Seen, " seen"}, {n.Loop, " loop"}, {n.Excluded, " excluded"}, {g.OnBase(n), " base"}, {g.OnResidual(n), " residual"}} {
			if f.on {
				flags += f.word
			}
		}
		how := ""
		if depth > 0 {
			how = "(" + string(n.How) + ") "
		}
		fmt.Fprintf(&b, "%s%s%s%s\n", strings.Repeat("  ", depth), how, label, flags)
		for _, k := range n.Kids {
			walk(k, depth+1)
		}
	}
	walk(g.Root, 0)
	return b.String()
}

// ---- the structure --------------------------------------------------------------------------------------------

func TestStructureOfAThreatScenario(t *testing.T) {
	ws, rep := open(t, nil)
	g := graphOf(t, ws, rep, "update-package-tampering")
	want := `threat update-package-tampering
  (steps) any
    (steps) step modify-package-in-transit base residual
      (mitigated) control signed-packages residual
        (bypass) any
          (bypass) step steal-signing-key
    (steps) step sign-malicious-package
      (needs) step compromise-build-server
`
	if got := text(g); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if g.Steps != 4 || g.Controls != 1 || !g.Drawable() {
		t.Errorf("%d steps, %d controls", g.Steps, g.Controls)
	}
	if g.Root.Name != "Tampering with Update package" {
		t.Errorf("name %q", g.Root.Name)
	}
}

// A threat scenario can be used as a step of another one.
func TestAThreatScenarioInsideAnother(t *testing.T) {
	ws, rep := open(t, nil)
	g := graphOf(t, ws, rep, "api-interface-spoofing")
	got := text(g)
	for _, line := range []string{"step impersonate-gateway", "threat device-key-disclosure", "step extract-key-from-flash", "(mitigated) control key-in-secure-element"} {
		if !strings.Contains(got, line) {
			t.Errorf("the structure lacks %q:\n%s", line, got)
		}
	}
	if g.Steps != 2 || g.Controls != 1 {
		t.Errorf("%d steps, %d controls", g.Steps, g.Controls)
	}
}

func TestRowsAreTheTextOfTheStructure(t *testing.T) {
	ws, rep := open(t, nil)
	g := graphOf(t, ws, rep, "update-package-tampering")
	var full, short []string
	for _, r := range g.Rows(true) {
		full = append(full, fmt.Sprintf("%d %s %s %s", r.Depth, r.Label, r.Node.Kind, r.Node.ID))
	}
	for _, r := range g.Rows(false) {
		short = append(short, fmt.Sprintf("%d %s %s", r.Depth, r.Node.Kind, r.Node.ID))
	}
	wantFull := []string{
		"0  any ", "1  step modify-package-in-transit", "2 mitigated by control signed-packages", "3 can be bypassed by any ", "4  step steal-signing-key",
		"1  step sign-malicious-package", "2 needs step compromise-build-server",
	}
	if strings.Join(full, "|") != strings.Join(wantFull, "|") {
		t.Errorf("full rows:\n%s", strings.Join(full, "\n"))
	}
	if strings.Join(short, "|") != "0 any |1 step modify-package-in-transit|1 step sign-malicious-package" {
		t.Errorf("a step is not opened in the short form: %v", short)
	}
}

// A step or a control that more than one place needs is written in full once, and then only named.
func TestSharedStepsAreWrittenInFullOnce(t *testing.T) {
	steps := `step z:
  name: Z
  target: backend
  potential: {time: ET1, expertise: SE0, knowledge: KoIC0, window: WoO0, equipment: Eq0}
  scalability: Single Vehicle

step x:
  name: X
  target: backend
  potential: {time: ET1, expertise: SE0, knowledge: KoIC0, window: WoO0, equipment: Eq0}
  scalability: Single Vehicle
  preparedby: z

step y:
  name: Y
  target: backend
  potential: {time: ET1, expertise: SE0, knowledge: KoIC0, window: WoO0, equipment: Eq0}
  scalability: Single Vehicle
  preparedby: z
`
	ws, rep := open(t, map[string]string{
		"tara/attack-steps.yaml":     steps,
		"tara/controls.yaml":         "",
		"tara/threat-scenarios.yaml": "threat update-package-tampering:\n  name: T\n  damages: unsafe-software-runs\n  steps:\n    and:\n      - x\n      - y\n",
	})
	g := graphOf(t, ws, rep, "update-package-tampering")
	want := `threat update-package-tampering
  (steps) all
    (steps) step x base residual
      (needs) step z base residual
    (steps) step y base residual
      (needs) step z seen base residual
`
	if got := text(g); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if g.Steps != 3 {
		t.Errorf("z counts once: %d steps", g.Steps)
	}
}

// validate reports a loop as an error. The structure must still not run away if someone asks for one.
func TestALoopIsCutOff(t *testing.T) {
	steps := `step a:
  name: A
  target: backend
  potential: {time: ET1, expertise: SE0, knowledge: KoIC0, window: WoO0, equipment: Eq0}
  scalability: Single Vehicle
  preparedby: b

step b:
  name: B
  target: backend
  potential: {time: ET1, expertise: SE0, knowledge: KoIC0, window: WoO0, equipment: Eq0}
  scalability: Single Vehicle
  preparedby: a
`
	ws, rep := open(t, map[string]string{
		"tara/attack-steps.yaml":     steps,
		"tara/controls.yaml":         "",
		"tara/threat-scenarios.yaml": "threat update-package-tampering:\n  name: T\n  damages: unsafe-software-runs\n  steps:\n    or:\n      - a\n",
	})
	g := graphOf(t, ws, rep, "update-package-tampering")
	want := `threat update-package-tampering
  (steps) any
    (steps) step a
      (needs) step b
        (needs) step a loop
`
	if got := text(g); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestAControlThePolicyLeavesOutIsMarked(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "policy.yaml", "scalability:", "controls:\n  exclude: [signed-packages]\n\nscalability:")
	res := load.Load(dir)
	rep, _ := engine.Run(res.Workspace, engine.Options{})
	g := graphOf(t, res.Workspace, rep, "update-package-tampering")
	if got := text(g); !strings.Contains(got, "(mitigated) control signed-packages excluded") {
		t.Errorf("%s", got)
	}
}

func TestAnUnknownThreatScenarioHasNoGraph(t *testing.T) {
	ws, _ := open(t, nil)
	if attack.NewIndex(ws).Graph("nope", nil, nil) != nil {
		t.Error("no graph for a threat scenario that is not there")
	}
}

// ---- the outline of a path -----------------------------------------------------------------------------------

func outlineText(rows []attack.OutlineRow) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%s%s %s %s | %s\n", strings.Repeat("  ", r.Depth), r.Label, r.Node.Kind, r.Node.ID, r.Note)
	}
	return b.String()
}

func TestOutlineOfThePaths(t *testing.T) {
	ws, rep := open(t, nil)
	x := attack.NewIndex(ws)
	var r engine.Result
	for _, x := range rep.Threats {
		if x.Threat == "update-package-tampering" {
			r = x
		}
	}
	// before the controls: the step alone
	if got := outlineText(attack.Rows(x.PathOutline(r.Base.Best, false))); got != " step modify-package-in-transit | \n" {
		t.Errorf("%q", got)
	}
	// with the controls: the control that is defeated, under the step it protects
	if got, want := outlineText(attack.Rows(x.PathOutline(r.Residual.Best, true))), " step modify-package-in-transit | \n  mitigated by defeat signed-packages | defeated at its reduction\n"; got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// the path that goes round the control: the steps of the bypass hang under the control
	var bypass *engine.Path
	for i := range r.Residual.Others {
		for _, e := range r.Residual.Others[i].Elems {
			if e.Kind == "bypass" {
				bypass = &r.Residual.Others[i]
			}
		}
	}
	if bypass == nil {
		t.Fatal("the test project has a path that bypasses the control")
	}
	want := " step modify-package-in-transit | \n  mitigated by bypass signed-packages | bypassed by the steps below\n     step steal-signing-key | \n"
	if got := outlineText(attack.Rows(x.PathOutline(*bypass, true))); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// ---- the picture ---------------------------------------------------------------------------------------------

// checkPicture holds a picture to the rules the layout keeps.
func checkPicture(t *testing.T, p *attack.Picture) {
	t.Helper()
	if p.W <= 0 || p.H <= 0 || len(p.Boxes) == 0 {
		t.Fatalf("an empty picture: %v x %v with %d boxes", p.W, p.H, len(p.Boxes))
	}
	for i, b := range p.Boxes {
		for _, v := range []float64{b.X, b.Y, b.W, b.H} {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("box %d has a place that is not a number: %+v", i, b)
			}
		}
		if b.X < 0 || b.Y < 0 || b.X+b.W > p.W+0.5 || b.Y+b.H > p.H+0.5 {
			t.Errorf("box %d is outside the picture (%v x %v): %+v", i, p.W, p.H, b)
		}
		for j := i + 1; j < len(p.Boxes); j++ {
			o := p.Boxes[j]
			if b.X < o.X+o.W && o.X < b.X+b.W && b.Y < o.Y+o.H && o.Y < b.Y+b.H {
				t.Errorf("box %d (%s %s) and box %d (%s %s) lie over each other", i, b.Kind, b.ID, j, o.Kind, o.ID)
			}
		}
	}
	for i, l := range p.Lines {
		if len(l.Pts) < 2 {
			t.Errorf("line %d has fewer than two places", i)
			continue
		}
		from, to := p.Boxes[l.From], p.Boxes[l.To]
		first, last := l.Pts[0], l.Pts[len(l.Pts)-1]
		if first.X > from.X+from.W+0.5 || first.X < from.X {
			t.Errorf("line %d starts at x=%v, not at the box it comes from (%v to %v)", i, first.X, from.X, from.X+from.W)
		}
		if last.X < to.X-0.5 || last.X > to.X+to.W {
			t.Errorf("line %d ends at x=%v, not at the box it goes to (%v to %v)", i, last.X, to.X, to.X+to.W)
		}
		for k := 1; k < len(l.Pts); k++ {
			if l.Pts[k].X < l.Pts[k-1].X {
				t.Errorf("line %d runs backwards at place %d", i, k)
			}
		}
	}
}

func TestLayoutOfTheTestProject(t *testing.T) {
	ws, rep := open(t, nil)
	for _, r := range rep.Threats {
		g := graphOf(t, ws, rep, r.Threat)
		p := attack.Layout(g)
		checkPicture(t, p)
		if len(p.Boxes) < g.Steps+g.Controls+1 {
			t.Errorf("%s: %d boxes for %d steps, %d controls and the threat scenario", r.Threat, len(p.Boxes), g.Steps, g.Controls)
		}
		again := attack.Layout(g)
		if fmt.Sprintf("%+v", p) != fmt.Sprintf("%+v", again) {
			t.Errorf("%s: the same graph must give the same picture", r.Threat)
		}
	}
}

// A project far larger than any real one: forty steps in layers, several of them needed by many.
func TestLayoutOfALargeRandomGraph(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var steps, ids strings.Builder
	const n = 40
	for i := 0; i < n; i++ {
		fmt.Fprintf(&steps, "step s%d:\n  name: Step number %d with a name that is long enough to wrap onto lines\n  target: backend\n  potential: {time: ET1, expertise: SE1, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  scalability: Single Vehicle\n", i, i)
		if i > 0 {
			fmt.Fprintf(&steps, "  preparedby:\n    and:\n")
			for k := 0; k < 1+rng.Intn(3); k++ {
				fmt.Fprintf(&steps, "      - s%d\n", rng.Intn(i))
			}
		}
		steps.WriteString("\n")
		ids.WriteString(fmt.Sprintf("      - s%d\n", i))
	}
	ws, rep := open(t, map[string]string{
		"tara/attack-steps.yaml":     steps.String(),
		"tara/controls.yaml":         "",
		"tara/threat-scenarios.yaml": "threat update-package-tampering:\n  name: T\n  damages: unsafe-software-runs\n  steps:\n    or:\n" + ids.String(),
	})
	g := graphOf(t, ws, rep, "update-package-tampering")
	if g.Steps != n {
		t.Fatalf("%d steps", g.Steps)
	}
	p := attack.Layout(g)
	checkPicture(t, p)
	if len(p.Boxes) < n+1 {
		t.Errorf("%d boxes", len(p.Boxes))
	}
}

func TestSVG(t *testing.T) {
	ws, rep := open(t, nil)
	g := graphOf(t, ws, rep, "update-package-tampering")
	p := attack.Layout(g)

	links := func(kind attack.Kind, id string) string { return "#" + string(kind) + "-" + id }
	svg := p.SVG("The attack on a package", "t1", true, true, links)
	wellFormed(t, svg)
	for _, want := range []string{
		`<svg class="ag"`, `role="img"`, `aria-label="The attack on a package"`,
		`<marker id="t1n"`, `<marker id="t1m"`, `<marker id="t1a"`, // the arrow heads of the three kinds of line
		"<title>step modify-package-in-transit: Change the package on the network</title>",
		"<title>control signed-packages", `<a href="#step-modify-package-in-transit">`,
		`class="key"`, "can be bypassed by",
	} {
		if !strings.Contains(svg, want) {
			t.Errorf("the picture lacks %s", want)
		}
	}
	// a picture without the key and the arrow heads is the part that a page puts in many times
	plain := p.SVG("x", "t2", false, false, nil)
	wellFormed(t, plain)
	if strings.Contains(plain, "<marker") || strings.Contains(plain, `class="key"`) || strings.Contains(plain, "<a href") {
		t.Error("no heads, no key, no links when they are not asked for")
	}
	if len(plain) >= len(svg) {
		t.Error("smaller without them")
	}

	stand := p.Standalone("x")
	wellFormed(t, stand)
	if !strings.Contains(stand, "<style>") || !strings.Contains(stand, `fill="#ffffff"`) || strings.Contains(stand, "<a href") {
		t.Error("a file of its own has its style and a white background and no links")
	}
	wellFormed(t, attack.Legend())
	if attack.CSS == "" || !strings.Contains(attack.CSS, ".ag") {
		t.Error("the style of the picture")
	}
}

// What is written in a record is text in the picture.
func TestSVGEscapesNames(t *testing.T) {
	evil := `<script>alert("x")</script> & "q"`
	steps := "step s:\n  name: '" + strings.ReplaceAll(evil, "'", "''") + "'\n  target: backend\n  potential: {time: ET1, expertise: SE0, knowledge: KoIC0, window: WoO0, equipment: Eq0}\n  scalability: Single Vehicle\n"
	ws, rep := open(t, map[string]string{
		"tara/attack-steps.yaml":     steps,
		"tara/controls.yaml":         "",
		"tara/threat-scenarios.yaml": "threat update-package-tampering:\n  name: T\n  damages: unsafe-software-runs\n  steps:\n    or:\n      - s\n",
	})
	svg := attack.Layout(graphOf(t, ws, rep, "update-package-tampering")).SVG("x", "t", false, true, nil)
	wellFormed(t, svg)
	if strings.Contains(svg, "<script>") {
		t.Error("a name is not markup")
	}
	if !strings.Contains(svg, "&lt;script&gt;") {
		t.Error("it is shown as text")
	}
}

func wellFormed(t *testing.T, svg string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(svg))
	for {
		if _, err := dec.Token(); err == io.EOF {
			return
		} else if err != nil {
			t.Fatalf("not well formed: %v\n%.300s", err, svg)
		}
	}
}

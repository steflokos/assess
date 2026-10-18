// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/testproject"
)

func page(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return mustRun(t, append(append([]string{"report", "-o", "-"}, args...), dir)...).out
}

var (
	idRe   = regexp.MustCompile(`\sid="([^"]+)"`)
	hrefRe = regexp.MustCompile(`\shref="#([^"]*)"`)
	tagRe  = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>`)
)

var voidTags = map[string]bool{"meta": true, "link": true, "br": true, "hr": true, "img": true, "input": true, "col": true, "path": true, "circle": true, "polygon": true, "marker": true, "title": false}

// tagsBalance checks that every element that is opened is closed, in order. It does not read what is inside script and
// style, and it takes the elements of the pictures that are written as <x/> as closed.
func tagsBalance(t *testing.T, html string) {
	t.Helper()
	html = regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(html, "<script></script>")
	html = regexp.MustCompile(`(?s)<style.*?</style>`).ReplaceAllString(html, "<style></style>")
	var stack []string
	for _, m := range tagRe.FindAllStringSubmatch(html, -1) {
		closing, name, rest := m[1] == "/", strings.ToLower(m[2]), m[3]
		if voidTags[name] || strings.HasSuffix(strings.TrimSpace(rest), "/") {
			continue
		}
		if !closing {
			stack = append(stack, name)
			continue
		}
		if len(stack) == 0 || stack[len(stack)-1] != name {
			top := "nothing"
			if len(stack) > 0 {
				top = stack[len(stack)-1]
			}
			t.Fatalf("</%s> closes %s", name, top)
		}
		stack = stack[:len(stack)-1]
	}
	if len(stack) != 0 {
		t.Fatalf("not closed: %v", stack)
	}
}

func TestReportIsOneSelfContainedPage(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "report", dir)
	if r.code != 0 || !strings.Contains(r.err, "wrote "+filepath.Join(dir, "out", "report.html")) || !strings.Contains(r.err, "0 open items") {
		t.Fatalf("exit %d\n%s", r.code, r.err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out", "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if !strings.HasPrefix(html, "<!doctype html>") {
		t.Errorf("%.40s", html)
	}
	if out := page(t, dir); out != html {
		t.Error("-o - writes the same page that the default file holds")
	}

	// nothing is loaded from the network, and the one script is the one of the report
	for _, bad := range []string{`src="http`, `href="http`, "url(http", "@import", "<iframe", "<link "} {
		if strings.Contains(html, bad) {
			t.Errorf("a report is one file. It must not contain %q", bad)
		}
	}
	if n := strings.Count(html, "<script"); n != 1 {
		t.Errorf("one script, got %d", n)
	}
	if !strings.Contains(html, "Content-Security-Policy") {
		t.Error("the page carries its own security policy")
	}

	for _, want := range []string{
		"Test gateway", "A gateway that receives signed software packages", "ISO/SAE 21434:2021", "Test engineer", "2026-01-15",
		"material for a review, not a statement of compliance",
		"update-package-tampering", "unsafe-software-runs", "signed-packages", "modify-package-in-transit",
		"Fingerprint of the input", "Made by", "assess " + model.ToolVersion,
		"TEST-001",          // the sources
		"Contacts", "Scope", // the extra blocks
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report does not say %q", want)
		}
	}
	// the fingerprint is the one that export gives
	if fp := fingerprintOf(t, dir); !strings.Contains(html, fp) {
		t.Errorf("the fingerprint %s is not in the report", fp)
	}
}

func TestReportIsTheSameEveryTime(t *testing.T) {
	a, b := testproject.Copy(t), testproject.Copy(t)
	if page(t, a) != page(t, b) {
		t.Error("the same files give the same page: no clock, no folder, no order of a map")
	}
}

func TestEveryLinkOfTheReportHasATarget(t *testing.T) {
	dir := testproject.Copy(t)
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", dir)
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Share", "treatment: Accept")
	html := page(t, dir)

	ids := map[string]int{}
	for _, m := range idRe.FindAllStringSubmatch(html, -1) {
		ids[m[1]]++
	}
	for id, n := range ids {
		if n > 1 {
			t.Errorf("the id %q is used %d times", id, n)
		}
	}
	links := 0
	for _, m := range hrefRe.FindAllStringSubmatch(html, -1) {
		links++
		if m[1] != "" && m[1] != "top" && ids[m[1]] == 0 {
			t.Errorf("a link to #%s, which is nowhere on the page", m[1])
		}
	}
	if links < 50 {
		t.Errorf("only %d links. The report links ids, parts and rows", links)
	}
}

func TestReportIsWellFormed(t *testing.T) {
	dir := testproject.Copy(t)
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", dir)
	tagsBalance(t, page(t, dir))
}

// A record can hold any text, and the report must show it as text. Nothing that a person writes in a record may run
// in the page.
func TestReportEscapesEverythingThatIsWritten(t *testing.T) {
	dir := testproject.Copy(t)
	evil := `<script>alert("x")</script> & <img src=x onerror=alert(1)>`
	testproject.Replace(t, dir, "project.yaml", "name: Test gateway", "name: 'Test <b>gateway</b>'")
	testproject.Replace(t, dir, "project.yaml", "description: A gateway that receives signed software packages from a backend and installs them.", `description: '`+strings.ReplaceAll(evil, "'", "''")+` A gateway.'`)
	testproject.Replace(t, dir, "item/architecture.yaml", "name: Backend\n", "name: 'Back <i>end</i>'\n")
	testproject.Replace(t, dir, "tara/attack-steps.yaml", "name: Change the package on the network", "name: '"+strings.ReplaceAll(evil, "'", "''")+"'")
	testproject.Replace(t, dir, "concept/risks.yaml", "reference: [TEST-101]", "reference: ['<a href=\"javascript:alert(1)\">x</a>']")
	html := page(t, dir)
	for _, bad := range []string{"<script>alert", "<img src=x", "<b>gateway</b>", "<i>end</i>", `<a href="javascript:`} {
		if strings.Contains(html, bad) {
			t.Errorf("the report holds %q as markup", bad)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;alert") {
		t.Error("the text is shown, as text")
	}
	if n := strings.Count(html, "<script"); n != 1 {
		t.Errorf("only the script of the report, got %d", n)
	}
	tagsBalance(t, html)
}

func TestReportListsWhatIsOpen(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "concept/risks.yaml", "  treatment: Accept\n", "  treatment:\n")
	r := run(t, "report", "-o", filepath.Join(t.TempDir(), "r.html"), dir)
	if r.code != 0 || !strings.Contains(r.err, "1 open item") {
		t.Errorf("exit %d\n%s", r.code, r.err)
	}
	if r := run(t, "report", "-strict", "-o", filepath.Join(t.TempDir(), "r.html"), dir); r.code != 1 {
		t.Errorf("-strict fails while anything is open: exit %d", r.code)
	}
	html := page(t, dir)
	if !strings.Contains(html, "risk device-key-disclosure has no treatment decision yet") {
		t.Error("the open item is listed")
	}
	// a value that is not there shows as open, not as 0
	if !strings.Contains(html, `<td class="open"><div>open <span class="note">no decision yet</span></div></td>`) {
		t.Error("an open value is written open, with what is missing")
	}
}

func TestReportNeedsAProjectWithoutErrors(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  colour: red\n")
	r := run(t, "report", dir)
	if r.code != 1 || !strings.Contains(r.err, "the project has errors") {
		t.Errorf("exit %d\n%s", r.code, r.err)
	}
	if exists(dir, "out/report.html") {
		t.Error("no report from a project with errors")
	}
}

// ---- page templates ------------------------------------------------------------------------------------------

func template(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "layout.html")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTemplateErrorsNameTheFileTheLineAndTheColumn(t *testing.T) {
	dir := testproject.Copy(t)
	cases := []struct {
		name, text, want string
	}{
		{"a placeholder that does not exist", "<p>\n{{nothing}}\n", `layout.html:2:1: error: [template] there is no placeholder "nothing"`},
		{"a part that does not exist", "{{section:nosuch}}", `layout.html:1:1: error: [template] there is no part "nosuch"`},
		{"a column that does not exist", "{{section:risk hide=nocolumn}}", `no table in "risk" has a column "nocolumn". The columns you can leave out are`},
		{"a sub-part that does not exist", "{{section:risk omit=zzz}}", `"zzz" is not a part of "risk"`},
		{"a part twice", "{{section:risk}}{{section:risk}}", `layout.html:1:17: error: [template] "risk" is already placed, at line 1`},
		{"a part inside a part that is placed", "{{section:tara}}{{section:risk}}", `"risk" is already placed, as part of "tara"`},
		{"a placeholder that is not closed", "{{cover", "{{ is not closed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := template(t, c.text)
			r := run(t, "report", "-template", path, "-o", filepath.Join(t.TempDir(), "r.html"), dir)
			if r.code != 1 || !strings.Contains(r.err, c.want) || !strings.Contains(r.err, "the template has 1 error. Fix them first") {
				t.Errorf("exit %d\n%s", r.code, r.err)
			}
			// the error names the file that the author wrote, whatever the mistake is
			if !strings.Contains(r.err, path) {
				t.Errorf("the message must name %s:\n%s", path, r.err)
			}
		})
	}
	out := filepath.Join(t.TempDir(), "r.html")
	run(t, "report", "-template", template(t, "{{nothing}}"), "-o", out, dir)
	if _, err := os.Stat(out); err == nil {
		t.Error("a template with a mistake writes no report")
	}
	if r := run(t, "report", "-template", filepath.Join(t.TempDir(), "none.html"), dir); r.code != 2 {
		t.Errorf("a template that is not there: exit %d", r.code)
	}
}

func TestATemplateChoosesTheParts(t *testing.T) {
	dir := testproject.Copy(t)
	path := template(t, `{{# a note for the editor. It is not written to the page }}
<!doctype html><html><head>{{meta}}{{csp}}{{style}}<title>{{title}}</title></head><body>
<p id="mine">{{title}} / {{standards}} / {{assessors}} / {{date}} / {{item}} / {{open}}</p>
{{cover.facts}}
{{section:item omit=functions,assumptions}}
{{section:risk hide=basedecidedby,residualdecidedby}}
</body></html>`)
	r := run(t, "report", "-template", path, "-o", "-", dir)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.err)
	}
	html := r.out
	if !strings.Contains(html, `<p id="mine">Test gateway / ISO/SAE 21434:2021 / Test engineer / 2026-01-15 / Test gateway / 0</p>`) {
		t.Errorf("the values are placed:\n%.600s", html)
	}
	if strings.Contains(html, "a note for the editor") {
		t.Error("a note is not written to the page")
	}
	if !strings.Contains(r.err, "the template leaves out") || !strings.Contains(r.err, "appendix") {
		t.Errorf("say what the template leaves out:\n%s", r.err)
	}
	// parts that are not placed are not on the page
	for _, absent := range []string{`id="appendix"`, `id="tara"`, `id="concept"`} {
		if strings.Contains(html, absent) {
			t.Errorf("%s is not placed", absent)
		}
	}
	// the sub-parts that were left out are not there, the rest of the part is
	if strings.Contains(html, `id="functions"`) || strings.Contains(html, `id="assumptions"`) || !strings.Contains(html, `id="architecture"`) {
		t.Error("omit leaves the named sub-parts out of the part")
	}
	// a link to a part that is not on the page is plain text
	for _, m := range hrefRe.FindAllStringSubmatch(html, -1) {
		if m[1] != "" && !strings.Contains(html, `id="`+m[1]+`"`) {
			t.Errorf("a link to #%s that is not on the page", m[1])
		}
	}
	// hide leaves columns out of the tables of the part
	tableHeads := regexp.MustCompile(`(?s)<th[^>]*>(.*?)</th>`).FindAllStringSubmatch(html, -1)
	var heads []string
	for _, h := range tableHeads {
		heads = append(heads, strings.TrimSpace(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(h[1], "")))
	}
	for _, h := range heads {
		if h == "Residual decided by" || h == "Base decided by" {
			t.Errorf("column %q was hidden", h)
		}
	}
	tagsBalance(t, html)
}

func TestTheTemplateOfAssessYamlIsUsedAndTheFlagWins(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "mine.html", "<p>from assess.yaml: {{title}}</p>")
	testproject.Replace(t, dir, "assess.yaml", "version: v0.1.0", "version: v0.1.0\ntemplate: mine.html")
	if out := page(t, dir); out != "<p>from assess.yaml: Test gateway</p>" {
		t.Errorf("%q", out)
	}
	if out := page(t, dir, "-template", template(t, "<p>from the flag</p>")); out != "<p>from the flag</p>" {
		t.Errorf("%q", out)
	}
	// a template that is not in the project is refused when the project is loaded
	testproject.Replace(t, dir, "assess.yaml", "template: mine.html", "template: ../elsewhere.html")
	_, env := runJSON(t, "validate", dir)
	if _, ok := env.find("unreadable"); !ok {
		t.Errorf("the template must be inside the project: %v", env.Diagnostics)
	}
	testproject.Replace(t, dir, "assess.yaml", "template: ../elsewhere.html", "template: missing.html")
	if _, env := runJSON(t, "validate", dir); len(env.errors()) != 1 || env.errors()[0].Code != "missing-file" {
		t.Errorf("a template that is not there is named: %v", env.Diagnostics)
	}
}

// The template is part of what the page is made from, so it joins the fingerprint.
func TestTheTemplateJoinsTheFingerprint(t *testing.T) {
	dir := testproject.Copy(t)
	standard := page(t, dir)
	custom := page(t, dir, "-template", template(t, "{{section:files}}"))
	fp := fingerprintOf(t, dir)
	if !strings.Contains(standard, fp) {
		t.Error("the standard page has the fingerprint of the files")
	}
	if strings.Contains(custom, fp) {
		t.Error("with a template of its own the page is made from more than the files, so it has another fingerprint")
	}
}

func TestStandardTemplateRoundTrip(t *testing.T) {
	dir := testproject.Copy(t)
	path := template(t, mustRun(t, "template").out)
	// the standard template gives the standard page, apart from the fingerprint that names the template
	a := page(t, dir)
	b := page(t, dir, "-template", path)
	strip := regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	if strip.ReplaceAllString(a, "") != strip.ReplaceAllString(b, "") {
		t.Error("the standard template written to a file gives the same page as the built-in one")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/schema"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// AssetsFile is where the asset records are written, relative to the project.
const AssetsFile = "tara/assets.yaml"

const assetsHeader = `# Assets: the parts of the architecture that matter for cybersecurity, with the properties that need protection.
# Write an asset as asset <element-id>: with the id of its element in item/. An element with no record is not an asset.
# assess generate assets wrote a record for every element, with all five properties. Edit it:
#   remove the properties that do not apply (a property belongs here because losing it leads to a damage scenario),
#   delete the record of an element that is only context.
# assess generate -force assets starts again from the architecture and replaces this file.
`

// AssetsResult is what Assets works out.
type AssetsResult struct {
	Text     string   // the records, each after a blank line
	Elements []string // the ids of the elements they are written for
}

// Assets returns an asset record for every element of the architecture, with all the
// cybersecurity properties: components, then interfaces, channels and data, each in the
// order of the files. It is a starting point to prune, written once.
func Assets(ws *model.Workspace) AssetsResult {
	props := strings.Join(iso21434.PropertyValues(), ", ")
	var res AssetsResult
	var b strings.Builder
	for _, e := range ws.Elements() {
		r := e.Base()
		res.Elements = append(res.Elements, r.ID)
		fmt.Fprintf(&b, "\nasset %s:\n  name: %s\n  properties: [%s]\n", r.ID, scalar(r.Name), props)
	}
	res.Text = b.String()
	return res
}

// WriteAssets writes the asset records to the assets file of the project in dir. It writes
// once: when the file exists it changes nothing and reports false, unless force is set, which
// replaces the file. It returns the path.
func WriteAssets(dir string, res AssetsResult, force bool) (path string, wrote bool, err error) {
	path = filepath.Join(dir, filepath.FromSlash(AssetsFile))
	if _, statErr := os.Stat(path); statErr == nil && !force {
		return path, false, nil
	}
	if len(res.Elements) == 0 {
		return path, false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return path, false, err
	}
	return path, true, atomic.WriteFile(path, []byte(schema.Modeline(AssetsFile)+assetsHeader+res.Text), 0o644)
}

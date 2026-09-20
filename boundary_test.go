package agentpolicy

import (
	"go/build"
	"path/filepath"
	"strings"
	"testing"
)

// TestImportBoundary enforces the rule that the module imports
// openresponses, agenttool, agentturn and the standard library only,
// in every package: the root and guard never call a model, and only
// classify takes a Streamer, but none of them may bring another
// dependency in.
func TestImportBoundary(t *testing.T) {
	allowed := map[string]bool{
		"github.com/ChristopherDavenport/openresponses": true,
		"github.com/ChristopherDavenport/agenttool":     true,
		"github.com/ChristopherDavenport/agentturn":     true,
	}
	for _, dir := range []string{".", "guard", "classify"} {
		pkg, err := build.Default.ImportDir(filepath.FromSlash(dir), 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range append(pkg.Imports, pkg.TestImports...) {
			switch {
			case !strings.Contains(imp, "."):
				// standard library
			case allowed[imp]:
			case strings.HasPrefix(imp, "github.com/ChristopherDavenport/openresponses/"):
				// echo and streamtest, in tests
			case strings.HasPrefix(imp, "github.com/ChristopherDavenport/agentpolicy"):
			default:
				t.Errorf("%s imports %q; only openresponses, agenttool, agentturn and the standard library are allowed", pkg.Name, imp)
			}
		}
	}
}

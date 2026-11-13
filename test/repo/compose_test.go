// Package repo checks files of the repository that no Go package holds.
package repo

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// image matches an image reference of a Tule service.
var image = regexp.MustCompile(`ghcr\.io/tulehq/[a-z-]+(:[^\s"']*)?`)

// pinned is a release version tag.
var pinned = regexp.MustCompile(`^:\d+\.\d+\.\d+$`)

// TestComposeImagesArePinned checks that compose.yaml, and its copy in the
// README, name every image by a release version, never latest or none.
func TestComposeImagesArePinned(t *testing.T) {
	compose, err := os.ReadFile("../../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	r := string(readme)
	start := strings.Index(r, "```yaml\n")
	end := strings.Index(r[start+1:], "```\n")
	if start < 0 || end < 0 {
		t.Fatal("the README shows no compose file")
	}
	for name, text := range map[string]string{
		"compose.yaml": string(compose), "README.md": r[start : start+1+end],
	} {
		refs := image.FindAllStringSubmatch(text, -1)
		if len(refs) != 8 {
			t.Fatalf(
				"%s names %d images, want the 8 of every service and the console",
				name,
				len(refs),
			)
		}
		for _, ref := range refs {
			if !pinned.MatchString(ref[1]) {
				t.Errorf("%s: %s is not pinned to a release", name, ref[0])
			}
		}
	}
}

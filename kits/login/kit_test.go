package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheBrowserHelpersAreTheSDKCopy keeps a deliberate duplicate from drifting.
//
// public/webauthn.js is sdk/node/src/browser.js, byte for byte. It is copied
// rather than imported because this kit embeds its assets and go:embed cannot
// reach outside the package directory, and because the file's own comment says
// it has no imports so that it can go into a page as it is.
//
// The copy is the part every WebAuthn integration gets wrong: the conversion
// between the base64url of WebAuthn's JSON form and the ArrayBuffers
// navigator.credentials wants. Two versions of that would be one version that
// is wrong.
func TestTheBrowserHelpersAreTheSDKCopy(t *testing.T) {
	const rel = "../../sdk/node/src/browser.js"

	source, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("read the SDK helpers: %v", err)
	}
	copied, err := os.ReadFile("public/webauthn.js")
	if err != nil {
		t.Fatalf("read the copy: %v", err)
	}
	if !bytes.Equal(source, copied) {
		t.Fatalf("public/webauthn.js differs from %s.\n"+
			"They are one file in two places on purpose. Copy it again:\n"+
			"  cp sdk/node/src/browser.js kits/login/public/webauthn.js", rel)
	}
}

// TestTheAssetsAreEmbedded catches the build that ships a page with no page in
// it, which is the failure mode of go:embed and is silent until somebody opens
// the site.
func TestTheAssetsAreEmbedded(t *testing.T) {
	for _, name := range []string{"public/index.html", "public/app.js", "public/style.css", "public/webauthn.js"} {
		b, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Errorf("%s is not embedded: %v", name, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("%s is embedded and empty", name)
		}
	}
}

// TestTheApiKeyNeverReachesTheBrowser is the property this kit exists to
// demonstrate, so it is asserted rather than described.
//
// A key in a served asset is a key every visitor holds, carrying whatever
// scopes it was minted with: enrol an authenticator for any subject, issue
// recovery codes for any subject, learn whether a given person has an account.
func TestTheApiKeyNeverReachesTheBrowser(t *testing.T) {
	err := fs.WalkDir(assets, "public", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, readErr := fs.ReadFile(assets, path)
		if readErr != nil {
			return readErr
		}
		body := string(b)
		for _, forbidden := range []string{"N0PASSTEMPS_API_KEY", "Authorization", "npa_"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s mentions %q; the browser half must never carry a credential", path, forbidden)
			}
		}
		// Every call the page makes is to this origin. An absolute URL to the
		// service would mean the browser talking to it directly, which it
		// cannot do without a key.
		if strings.Contains(body, "fetch(\"http") || strings.Contains(body, "fetch(`http") {
			t.Errorf("%s fetches an absolute URL; the page talks to /api on its own origin", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

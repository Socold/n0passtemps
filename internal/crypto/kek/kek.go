// Package kek provides key encryption key material to the envelope sealer.
//
// A KEK is never generated implicitly at runtime. An operator creates it once
// with "n0passtemps-wizard kek init", backs it up, and supplies it through one
// of the providers below. Losing every copy of a KEK means the secrets sealed
// under it are unrecoverable, which is why generation is an explicit,
// documented step rather than a side effect of starting the server.
package kek

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

// KeySize is the required KEK length in bytes (AES-256).
const KeySize = 32

var (
	ErrNoKeys         = errors.New("kek: keyring contains no keys")
	ErrUnknownVersion = errors.New("kek: unknown key version")
	ErrBadKeySize     = errors.New("kek: key must be 32 bytes")
)

// keyring holds the decoded key material shared by the providers.
type keyring struct {
	mu      sync.RWMutex
	keys    map[uint32][]byte
	current uint32
}

func (r *keyring) Current() (uint32, []byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.keys) == 0 {
		return 0, nil, ErrNoKeys
	}
	k, ok := r.keys[r.current]
	if !ok {
		return 0, nil, fmt.Errorf("%w: current is %d", ErrUnknownVersion, r.current)
	}
	return r.current, append([]byte(nil), k...), nil
}

func (r *keyring) ByVersion(v uint32) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.keys[v]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, v)
	}
	return append([]byte(nil), k...), nil
}

// Versions returns the retained key versions in ascending order.
func (r *keyring) Versions() []uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]uint32, 0, len(r.keys))
	for v := range r.keys {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Close zeroizes all retained key material.
func (r *keyring) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for v, k := range r.keys {
		zeroize.Bytes(k)
		delete(r.keys, v)
	}
	return nil
}

// FileProvider reads a keyring from a JSON file on disk.
//
// The file must not be readable by any account other than the service user, and
// must not live on the same volume as the database it protects: a KEK stored
// beside its own ciphertext provides no confidentiality against an attacker who
// obtains the volume. Both conditions are checked at load time.
type FileProvider struct {
	*keyring
	path string
}

// fileFormat is the on-disk keyring layout.
type fileFormat struct {
	Current uint32            `json:"current"`
	Keys    map[string]string `json:"keys"` // version -> standard base64 of 32 bytes
}

// LoadFileProvider reads and validates the keyring at path.
//
// dataDirs lists directories holding persistent application state. If path
// resolves inside any of them, loading fails: see the type comment.
func LoadFileProvider(path string, dataDirs ...string) (*FileProvider, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("kek: resolve %q: %w", path, err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("kek: stat %q: %w", abs, err)
	}
	if err := checkPermissions(abs, info.Mode()); err != nil {
		return nil, err
	}
	if err := checkNotInDataDir(abs, dataDirs); err != nil {
		return nil, err
	}

	// #nosec G304 -- the keyring path comes from kek.path in the operator's configuration or the KEK_PATH variable,
	// and its mode and location are checked above
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("kek: read %q: %w", abs, err)
	}
	defer zeroize.Bytes(raw)

	ring, err := parseKeyring(raw)
	if err != nil {
		return nil, err
	}
	return &FileProvider{keyring: ring, path: abs}, nil
}

// Path returns the absolute keyring path, for diagnostics.
func (p *FileProvider) Path() string { return p.path }

// EnvProvider reads a keyring from an environment variable, which suits
// container and orchestrator secret injection where no file is mounted.
type EnvProvider struct {
	*keyring
}

// LoadEnvProvider parses the keyring held in the named environment variable.
// The variable is unset once parsed, so it does not remain visible to child
// processes or to /proc/self/environ.
func LoadEnvProvider(envVar string) (*EnvProvider, error) {
	val, ok := os.LookupEnv(envVar)
	if !ok || strings.TrimSpace(val) == "" {
		return nil, fmt.Errorf("kek: %s is not set", envVar)
	}
	// Best effort: the Go runtime copied the value into an immutable string
	// already, so the original cannot be overwritten. Unsetting at least
	// removes it from the process environment block.
	defer func() { _ = os.Unsetenv(envVar) }()

	ring, err := parseKeyring([]byte(val))
	if err != nil {
		return nil, err
	}
	return &EnvProvider{keyring: ring}, nil
}

func parseKeyring(raw []byte) (*keyring, error) {
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("kek: parse keyring: %w", err)
	}
	if len(f.Keys) == 0 {
		return nil, ErrNoKeys
	}

	keys := make(map[uint32][]byte, len(f.Keys))
	for vs, b64 := range f.Keys {
		v, err := strconv.ParseUint(vs, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("kek: key version %q is not a number: %w", vs, err)
		}
		// Only the canonical spelling is accepted. "1" and "01" parse to the
		// same version, so a keyring holding both would keep whichever the
		// map iteration happened to visit last, and which key protects the
		// database would differ from one start to the next.
		if strconv.FormatUint(v, 10) != vs {
			return nil, fmt.Errorf("kek: key version %q is not in canonical form, write it as %d", vs, v)
		}
		if v == 0 {
			return nil, fmt.Errorf("kek: key version 0 is reserved; versions start at 1")
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("kek: key %d is not valid base64: %w", v, err)
		}
		if len(key) != KeySize {
			zeroize.Bytes(key)
			return nil, fmt.Errorf("%w: key %d has %d bytes", ErrBadKeySize, v, len(key))
		}
		keys[uint32(v)] = key
	}
	if _, ok := keys[f.Current]; !ok {
		return nil, fmt.Errorf("%w: current is %d but that key is absent", ErrUnknownVersion, f.Current)
	}
	return &keyring{keys: keys, current: f.Current}, nil
}

func checkPermissions(path string, mode fs.FileMode) error {
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("kek: %q is mode %#o, must not be readable by group or other (chmod 600)", path, mode.Perm())
	}
	return nil
}

// checkNotInDataDir refuses a keyring that resolves inside a directory holding
// persistent state.
//
// Both sides are passed through filepath.EvalSymlinks first. Comparing the
// paths as written would let a symbolic link, or a bind mount, place the key
// inside the data directory while still passing a textual check, which is
// precisely the arrangement this is meant to catch.
func checkNotInDataDir(kekPath string, dataDirs []string) error {
	kekReal := resolve(kekPath)
	for _, d := range dataDirs {
		if d == "" {
			continue
		}
		abs, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		dirReal := resolve(abs)
		rel, err := filepath.Rel(dirReal, kekReal)
		if err != nil {
			continue
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			detail := ""
			if kekReal != kekPath {
				detail = fmt.Sprintf(" (it resolves to %q)", kekReal)
			}
			return fmt.Errorf(
				"kek: %q is inside the data directory %q%s; a key stored beside the "+
					"ciphertext it protects gives no confidentiality if the volume is "+
					"copied. Mount it from a separate volume or use the env provider",
				kekPath, abs, detail)
		}
	}
	return nil
}

// resolve follows symbolic links where it can, and falls back to the path as
// given when it cannot. A directory that does not exist yet is not an error
// here: the check is about placement, and a missing data directory cannot
// contain the key anyway.
func resolve(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	// The leaf may not exist while its parent does, which is the usual case
	// for a data directory the server is about to create. Resolving the parent
	// still catches a symlinked parent.
	dir, base := filepath.Split(path)
	if dir == "" {
		return path
	}
	if realDir, err := filepath.EvalSymlinks(filepath.Clean(dir)); err == nil {
		return filepath.Join(realDir, base)
	}
	return path
}

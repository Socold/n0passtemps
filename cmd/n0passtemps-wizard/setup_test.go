package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/config"
)

// The wizard is the whole of the product's installation story: the
// specification's support model is documentation and a GitHub issue tracker,
// and its five-minute install runs this and then docker compose. A wizard that
// emits a configuration the service refuses is therefore not a rough edge, it is
// the one failure the model cannot absorb, because the operator has nobody to
// ask and no reason to suspect the generator rather than their own answers.
//
// runSetup already guards against it: it renders, writes to a temporary file,
// loads it and refuses to write anything if the load fails, with an error saying
// in as many words that this is a bug in the tool rather than in the answers.
// What follows exercises that guarantee over every combination of answers,
// which is what the interactive path cannot do.

// answerMatrix is every combination the six questions can produce that changes
// the generated files. The free-text answers are covered separately, because
// their validity is a property of the validator rather than of the renderer.
func answerMatrix() []answers {
	// The listeners, paired with the exposure answer askExposure would have
	// collected for each. A loopback listener is never asked, which is why its
	// exposure is empty.
	listeners := []struct {
		addr     string
		exposure string
	}{
		{"127.0.0.1:8080", ""},
		{"0.0.0.0:8080", "constrained"},
		{"0.0.0.0:8443", "tls"},
		{"0.0.0.0:8080", "proxy"},
	}

	var out []answers
	for _, deployment := range []string{"sqlite", "postgres"} {
		for _, lite := range []bool{false, true} {
			for _, adminUI := range []bool{false, true} {
				for _, l := range listeners {
					a := answers{
						Deployment: deployment,
						RPID:       "auth.example.com",
						Origin:     "https://auth.example.com",
						Addr:       l.addr,
						TenantName: "Example Ltd",
						Lite:       lite,
						AdminUI:    adminUI,
						Exposure:   l.exposure,
					}
					switch l.exposure {
					case "tls":
						a.TLSCert = "/etc/n0passtemps/tls/fullchain.pem"
						a.TLSKey = "/etc/n0passtemps/tls/privkey.pem"
					case "proxy":
						a.ProxyCIDRs = "10.0.0.0/8, 192.168.0.0/16"
					}
					if l.exposure != "" {
						a.AdminAllowList = "127.0.0.1/32"
					}
					out = append(out, a)
				}
			}
		}
	}
	return out
}

// name describes a combination for a subtest.
func (a answers) name() string {
	parts := []string{a.Deployment}
	if a.Lite {
		parts = append(parts, "lite")
	} else {
		parts = append(parts, "complete")
	}
	if a.AdminUI {
		parts = append(parts, "ui")
	} else {
		parts = append(parts, "no-ui")
	}
	if a.Exposure == "" {
		parts = append(parts, "loopback")
	} else {
		parts = append(parts, a.Exposure)
	}
	return strings.Join(parts, "/")
}

// loadRendered writes renderConfig's output and loads it the way runSetup does,
// with the two secrets that never go in the file supplied from the environment.
func loadRendered(t *testing.T, a answers) (*config.Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(renderConfig(a)), 0o600); err != nil {
		t.Fatalf("write rendered config: %v", err)
	}

	probe := map[string]string{
		config.EnvPrefix + "SUBJECT_PEPPER": base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	if a.Deployment == "postgres" {
		probe[config.EnvPrefix+"DATABASE_DSN"] =
			"postgres://n0passtemps:placeholder@postgres:5432/n0passtemps?sslmode=disable"
		probe[config.EnvPrefix+"DATABASE_ALLOW_PLAINTEXT"] = "true"
	}
	restore := withTemporaryEnv(probe)
	defer restore()
	return config.Load(path)
}

// TestEveryAnswerCombinationProducesAValidConfiguration is the property the
// tool promises and the one an operator cannot check for themselves.
func TestEveryAnswerCombinationProducesAValidConfiguration(t *testing.T) {
	for _, a := range answerMatrix() {
		t.Run(a.name(), func(t *testing.T) {
			cfg, err := loadRendered(t, a)
			if err != nil {
				t.Fatalf("the generated configuration does not load:\n%v", err)
			}
			if cfg.WebAuthn.RPID != a.RPID {
				t.Errorf("rp_id = %q, want %q", cfg.WebAuthn.RPID, a.RPID)
			}
			if len(cfg.WebAuthn.Origins) == 0 || cfg.WebAuthn.Origins[0] != a.Origin {
				t.Errorf("origins = %v, want [%s]", cfg.WebAuthn.Origins, a.Origin)
			}
			if cfg.Database.Driver != a.Deployment {
				t.Errorf("database.driver = %q, want %q", cfg.Database.Driver, a.Deployment)
			}
			if cfg.Admin.UIEnabled != a.AdminUI {
				t.Errorf("admin.ui_enabled = %t, want %t", cfg.Admin.UIEnabled, a.AdminUI)
			}
		})
	}
}

// TestLiteModeReachesTheFeatureFlags checks that answering "lite" produces the
// deployment the README's decision tree describes, rather than a file that says
// lite and behaves like the complete one.
func TestLiteModeReachesTheFeatureFlags(t *testing.T) {
	for _, a := range answerMatrix() {
		if a.Deployment != "sqlite" || !a.AdminUI || a.Exposure != "constrained" {
			continue
		}
		t.Run(a.name(), func(t *testing.T) {
			cfg, err := loadRendered(t, a)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.Features.LiteMode != a.Lite {
				t.Fatalf("features.lite_mode = %t, want %t", cfg.Features.LiteMode, a.Lite)
			}
			// Lite is a shorthand: the governance features go off with it, and
			// the recovery batch halves. Those are the differences README.md
			// tabulates, so they are the ones worth pinning here.
			if a.Lite {
				if cfg.Features.AdminRBAC || cfg.Features.DualApproval || cfg.Features.DeferredErasure {
					t.Errorf("lite left a governance feature on: rbac=%t approval=%t erasure=%t",
						cfg.Features.AdminRBAC, cfg.Features.DualApproval, cfg.Features.DeferredErasure)
				}
				if cfg.Recovery.CodeCount != 8 {
					t.Errorf("recovery.code_count = %d under lite, want 8", cfg.Recovery.CodeCount)
				}
			} else if !cfg.Features.AdminRBAC {
				t.Error("the complete deployment came out with admin_rbac off")
			}
		})
	}
}

// TestTheAdminUIOnANonLoopbackListenerCarriesAnAllowList is the rule
// validateAdmin enforces, checked here because the wizard is what produces the
// pairing.
//
// The interesting case is the one the matrix covers: the listener answer is
// 0.0.0.0:8080, which is not loopback, so a generated file that enables the
// console without an allow list would be refused by the service after the
// operator had already run compose.
func TestTheAdminUIOnANonLoopbackListenerCarriesAnAllowList(t *testing.T) {
	for _, a := range answerMatrix() {
		if !a.AdminUI || a.Exposure == "" {
			continue
		}
		t.Run(a.name(), func(t *testing.T) {
			cfg, err := loadRendered(t, a)
			if err != nil {
				t.Fatalf("the generated configuration does not load:\n%v", err)
			}
			if len(cfg.Admin.IPAllowList) == 0 {
				t.Errorf("admin.ui_enabled on %s with no admin.ip_allow_list", a.Addr)
			}
		})
	}
}

// TestTheExposureAnswerReachesTheListener checks that each of the three
// arrangements askExposure offers produces the settings that make it true,
// rather than a comment describing it.
//
// This is the defect the question was added for: the file used to carry the
// three options as commented examples, so any listener that was not loopback
// generated a configuration the service refuses, and the run ended telling the
// operator it was a bug in the tool.
func TestTheExposureAnswerReachesTheListener(t *testing.T) {
	for _, a := range answerMatrix() {
		if a.Exposure == "" {
			continue
		}
		t.Run(a.name(), func(t *testing.T) {
			cfg, err := loadRendered(t, a)
			if err != nil {
				t.Fatalf("the generated configuration does not load:\n%v", err)
			}
			switch a.Exposure {
			case "tls":
				if cfg.Server.TLSCertFile != a.TLSCert || cfg.Server.TLSKeyFile != a.TLSKey {
					t.Errorf("tls pair = %q/%q, want %q/%q",
						cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile, a.TLSCert, a.TLSKey)
				}
			case "proxy":
				if !cfg.Server.TrustProxy {
					t.Error("trust_proxy is off after the proxy answer")
				}
				if len(cfg.Server.TrustedProxyCIDRs) != 2 {
					t.Errorf("trusted_proxy_cidrs = %v, want the two networks answered",
						cfg.Server.TrustedProxyCIDRs)
				}
			case "constrained":
				if !cfg.Server.AllowPlaintext {
					t.Error("allow_plaintext is off after the constrained answer")
				}
			}
		})
	}
}

// TestListenerNeedsExposureAsksOnlyWhenItMust keeps the common path at six
// questions.
func TestListenerNeedsExposureAsksOnlyWhenItMust(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": false,
		"[::1]:8080":     false,
		"0.0.0.0:8080":   true,
		"192.0.2.10:443": true,
		"not-an-address": false, // caught by probeAddr instead
	} {
		if got := listenerNeedsExposure(addr); got != want {
			t.Errorf("listenerNeedsExposure(%q) = %t, want %t", addr, got, want)
		}
	}
}

// TestProbeAddrRejectsWhatIsNotAnAddress covers the prompt's own check.
func TestProbeAddrRejectsWhatIsNotAnAddress(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8080": true,
		"0.0.0.0:8080":   true,
		"8080":           false,
		"127.0.0.1":      false,
		"":               false,
	} {
		err := probeAddr(addr)
		if ok && err != nil {
			t.Errorf("probeAddr(%q) = %v, want accepted", addr, err)
		}
		if !ok && err == nil {
			t.Errorf("probeAddr(%q) was accepted", addr)
		}
	}
}

// TestRenderEnvCarriesNoSecretValue checks that the file the wizard marks 0600
// ships empty rather than pre-filled.
//
// A generated secret would be a secret this tool chose, printed to a file the
// operator is told to keep, and identical for anybody who ran the wizard on the
// same version if the generation were ever made deterministic. The variables are
// present and empty so the operator fills them from `wizard pepper`.
func TestRenderEnvCarriesNoSecretValue(t *testing.T) {
	for _, a := range answerMatrix() {
		t.Run(a.name(), func(t *testing.T) {
			env := renderEnv(a)
			for _, key := range []string{"N0PASSTEMPS_SUBJECT_PEPPER"} {
				line := key + "="
				if !strings.Contains(env, line+"\n") {
					t.Errorf("%s is not present and empty in .env", key)
				}
			}
			if a.Deployment == "postgres" && !strings.Contains(env, "POSTGRES_PASSWORD=\n") {
				t.Error("POSTGRES_PASSWORD is not present and empty in .env")
			}
			// The DSN references the password rather than carrying one.
			if strings.Contains(env, "postgres://n0passtemps:placeholder") {
				t.Error(".env carries a literal database password")
			}
		})
	}
}

// TestRenderComposeMatchesTheDeployment checks the shape an operator runs.
func TestRenderComposeMatchesTheDeployment(t *testing.T) {
	for _, a := range answerMatrix() {
		t.Run(a.name(), func(t *testing.T) {
			compose := renderCompose(a)
			if !strings.Contains(compose, "n0passtemps") {
				t.Fatal("the compose file names no service")
			}
			hasPostgres := strings.Contains(compose, "postgres:")
			if want := a.Deployment == "postgres"; hasPostgres != want {
				t.Errorf("compose declares a postgres service = %t, want %t", hasPostgres, want)
			}
			// The image is pinned, for the reason renderEnv states: a moving
			// tag makes a rollback impossible to describe.
			if strings.Contains(compose, ":latest") {
				t.Error("the compose file pins the image to a moving tag")
			}
		})
	}
}

// TestProbeRPIDRejectsWhatTheValidatorRejects keeps the prompt's check and the
// real check from drifting apart.
//
// probeRPID exists so a bad answer can be re-asked instead of failing the whole
// run at the end, which means it duplicates the validator's rules and can fall
// behind them.
func TestProbeRPIDRejectsWhatTheValidatorRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		rpID string
		ok   bool
	}{
		"a domain":      {"auth.example.com", true},
		"localhost":     {"localhost", true},
		"with a scheme": {"https://auth.example.com", false},
		"with a port":   {"auth.example.com:8443", false},
		"with a path":   {"auth.example.com/login", false},
		"an ip address": {"192.0.2.10", false},
		"empty":         {"", false},
	} {
		// Whitespace is deliberately not a case here. prompt trims the answer
		// before probeRPID ever sees it, so it cannot arrive this way, and
		// validateRPID does not reject it: "example.com " loads, validates, and
		// then fails in the browser, which refuses a ceremony whose relying
		// party does not match the origin's domain. That is a gap in the
		// validator rather than in this tool, and asserting it here would
		// record it in the wrong place.
		t.Run(name, func(t *testing.T) {
			err := probeRPID(tc.rpID)
			if tc.ok && err != nil {
				t.Errorf("probeRPID(%q) = %v, want accepted", tc.rpID, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("probeRPID(%q) was accepted", tc.rpID)
			}
		})
	}
}

// TestProbeOriginRequiresTheRelyingPartyToCoverIt is the pairing rule, which is
// the one an operator gets wrong without the browser saying which half is at
// fault.
func TestProbeOriginRequiresTheRelyingPartyToCoverIt(t *testing.T) {
	if err := probeOrigin("https://auth.example.com", "auth.example.com"); err != nil {
		t.Errorf("a matching origin was refused: %v", err)
	}
	if err := probeOrigin("https://login.other.example", "auth.example.com"); err == nil {
		t.Error("an origin outside the relying party was accepted")
	}
	if err := probeOrigin("not-a-url", "auth.example.com"); err == nil {
		t.Error("a malformed origin was accepted")
	}
}

// TestFirstRelevantErrorPicksTheLineAboutTheField is what keeps a prompt from
// printing every complaint about a configuration that is still half built.
func TestFirstRelevantErrorPicksTheLineAboutTheField(t *testing.T) {
	if got := firstRelevantError(nil, "rp_id"); got != nil {
		t.Errorf("no error produced %v", got)
	}

	cfg := config.Default()
	cfg.WebAuthn.RPID = ""
	cfg.WebAuthn.Origins = nil
	joined := cfg.Validate()
	if joined == nil {
		t.Fatal("an empty relying party validated")
	}

	got := firstRelevantError(joined, "rp_id")
	if got == nil {
		t.Fatal("no line about rp_id was found in the joined error")
	}
	if !strings.Contains(got.Error(), "rp_id") {
		t.Errorf("selected line %q does not mention rp_id", got)
	}
	if strings.Contains(got.Error(), "\n") {
		t.Errorf("selected %q, which is more than one line", got)
	}
	if firstRelevantError(joined, "no_such_field_anywhere") != nil {
		t.Error("a field nothing complained about produced an error")
	}
}

// TestTheClosingInstructionsMatchTheDeployment covers the two strings that
// change with it.
//
// They are small and they are the last thing the operator reads, so a lite
// deployment told to mint two administrators, or a complete one told to mint
// one, sends them to a command that fails or to a console one person can lock
// themselves out of.
func TestTheClosingInstructionsMatchTheDeployment(t *testing.T) {
	lite := answers{Lite: true}
	complete := answers{Lite: false}

	if adminsFlag(lite) != "" {
		t.Errorf("lite asks for %q, want no -admins flag", adminsFlag(lite))
	}
	if !strings.Contains(adminsFlag(complete), "-admins 2") {
		t.Errorf("the complete deployment asks for %q, want -admins 2", adminsFlag(complete))
	}
	if quorumWording(lite) != "" {
		t.Errorf("lite explains a quorum it does not have: %q", quorumWording(lite))
	}
	if !strings.Contains(quorumWording(complete), "dual approval") {
		t.Errorf("the complete deployment does not say why two: %q", quorumWording(complete))
	}
}

// TestWithTemporaryEnvRestoresWhatItFound matters because runSetup validates
// with two secrets set in the process, and leaving either behind would change
// the behaviour of everything that runs afterwards.
func TestWithTemporaryEnvRestoresWhatItFound(t *testing.T) {
	const present = "N0PASSTEMPS_TEST_PRESENT"
	const absent = "N0PASSTEMPS_TEST_ABSENT"

	t.Setenv(present, "original")
	if err := os.Unsetenv(absent); err != nil {
		t.Fatalf("unset: %v", err)
	}

	restore := withTemporaryEnv(map[string]string{present: "temporary", absent: "temporary"})
	if got := os.Getenv(present); got != "temporary" {
		t.Errorf("%s = %q during the call, want temporary", present, got)
	}
	if got := os.Getenv(absent); got != "temporary" {
		t.Errorf("%s = %q during the call, want temporary", absent, got)
	}

	restore()
	if got := os.Getenv(present); got != "original" {
		t.Errorf("%s = %q after restore, want original", present, got)
	}
	if _, ok := os.LookupEnv(absent); ok {
		t.Errorf("%s was left set after restore; it did not exist before", absent)
	}
}

// TestRunCheckAcceptsWhatSetupWrites joins the two halves of the tool: the file
// the wizard generates is the file its own check subcommand validates.
func TestRunCheckAcceptsWhatSetupWrites(t *testing.T) {
	a := answers{
		Deployment: "sqlite", RPID: "localhost", Origin: "http://localhost:8080",
		Addr: "127.0.0.1:8080", TenantName: "Example Ltd", Lite: true,
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(renderConfig(a)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	restore := withTemporaryEnv(map[string]string{
		config.EnvPrefix + "SUBJECT_PEPPER": base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	defer restore()

	if err := runCheck([]string{"-config", path}); err != nil {
		t.Fatalf("check refused the file setup writes: %v", err)
	}
	if err := runCheck([]string{"-config", filepath.Join(dir, "absent.toml")}); err == nil {
		t.Error("check accepted a file that does not exist")
	}
}

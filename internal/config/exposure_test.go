package config

import (
	"strings"
	"testing"
	"time"
)

// validExposedConfig is the shipped default with the two keys every Validate
// call needs, so that only the refusal under test shows up in the error.
func validExposedConfig() Config {
	cfg := Default()
	cfg.WebAuthn.RPID = "example.com"
	cfg.WebAuthn.Origins = []string{"https://example.com"}
	return cfg
}

// behindProxy is the arrangement most of the rules below are about: a loopback
// listener, a declared reverse proxy, and an allow list for the admin surface.
func behindProxy(c *Config) {
	c.Server.TrustProxy = true
	c.Server.TrustedProxyCIDRs = []string{"10.0.3.0/24"}
	c.Admin.IPAllowList = []string{"10.0.0.0/8"}
}

// refusal is one row of the tables below.
//
// Every string in refuse must appear in the error, which is how a row checks
// both that the setting is refused and that the message says what to do about
// it. An empty refuse means the configuration must be accepted.
type refusal struct {
	name   string
	tune   func(*Config)
	refuse []string
}

func runRefusals(t *testing.T, cases []refusal) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validExposedConfig()
			tc.tune(&cfg)

			err := cfg.Validate()
			if len(tc.refuse) == 0 {
				if err != nil {
					t.Errorf("a workable configuration was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want a refusal mentioning %q", tc.refuse[0])
			}
			for _, want := range tc.refuse {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not mention %q:\n%v", want, err)
				}
			}
		})
	}
}

// TestTrustedProxiesMustBeNetworksTheOperatorCanOwn covers the width rule.
//
// A forwarded client address is believed from every address in these networks,
// so a network that takes in strangers hands each of them the choice of the
// address rate limiting, the admin allow list and the audit trail rely on.
func TestTrustedProxiesMustBeNetworksTheOperatorCanOwn(t *testing.T) {
	proxies := func(cidrs ...string) func(*Config) {
		return func(c *Config) {
			behindProxy(c)
			c.Server.TrustedProxyCIDRs = cidrs
		}
	}
	runRefusals(t, []refusal{
		{"a single proxy", proxies("10.0.3.7/32"), nil},
		{"the whole of the largest private IPv4 block", proxies("10.0.0.0/8"), nil},
		{"the whole unique local IPv6 block", proxies("fc00::/7"), nil},
		{"the half of it that is actually assigned", proxies("fd00::/8"), nil},
		{
			name:   "every IPv4 address",
			tune:   proxies("0.0.0.0/0"),
			refuse: []string{`server.trusted_proxy_cidrs entry "0.0.0.0/0" is wider than /8`, "List the addresses"},
		},
		{
			name:   "every IPv6 address",
			tune:   proxies("::/0"),
			refuse: []string{`server.trusted_proxy_cidrs entry "::/0" is wider than /7`, "List the addresses"},
		},
		{
			name:   "every IPv4 address, written in its IPv6-mapped form",
			tune:   proxies("::ffff:0.0.0.0/96"),
			refuse: []string{`entry "::ffff:0.0.0.0/96" is wider than /8`},
		},
		{
			name:   "one bit wider than a private block",
			tune:   proxies("10.0.0.0/7"),
			refuse: []string{`entry "10.0.0.0/7" is wider than /8`},
		},
		{
			name:   "the global unicast IPv6 space",
			tune:   proxies("2000::/3"),
			refuse: []string{`entry "2000::/3" is wider than /7`},
		},
		{
			name:   "a narrow network beside one that is too wide",
			tune:   proxies("10.0.3.7/32", "0.0.0.0/1"),
			refuse: []string{`entry "0.0.0.0/1" is wider than /8`},
		},
	})
}

// TestAnAdminAllowListThatAdmitsEveryoneIsRefused covers the zero-length prefix.
func TestAnAdminAllowListThatAdmitsEveryoneIsRefused(t *testing.T) {
	list := func(cidrs ...string) func(*Config) {
		return func(c *Config) { c.Admin.IPAllowList = cidrs }
	}
	runRefusals(t, []refusal{
		{"a private network", list("10.0.0.0/8"), nil},
		{"a single workstation", list("192.0.2.10/32", "2001:db8::10/128"), nil},
		{
			name:   "every IPv4 address",
			tune:   list("0.0.0.0/0"),
			refuse: []string{`admin.ip_allow_list entry "0.0.0.0/0" admits every address`, "Replace it with"},
		},
		{
			name:   "every IPv6 address",
			tune:   list("::/0"),
			refuse: []string{`admin.ip_allow_list entry "::/0" admits every address`, "Replace it with"},
		},
		{
			name:   "every IPv4 address, written in its IPv6-mapped form",
			tune:   list("::ffff:0.0.0.0/96"),
			refuse: []string{`entry "::ffff:0.0.0.0/96" admits every address`},
		},
		{
			name:   "a real network beside the one that admits everyone",
			tune:   list("10.0.0.0/8", "0.0.0.0/0"),
			refuse: []string{`entry "0.0.0.0/0" admits every address`},
		},
	})
}

// TestTheAdminAllowListIsRequiredWhereverTheServiceCanBeReached covers the two
// arrangements that used to slip past: a loopback listener published by a
// reverse proxy, and a deployment with the console off whose /admin/v1 is still
// served on the same port.
func TestTheAdminAllowListIsRequiredWhereverTheServiceCanBeReached(t *testing.T) {
	const want = "admin.ip_allow_list is empty while the service is reachable beyond loopback"
	const remedy = "List the networks administrators connect from"

	runRefusals(t, []refusal{
		{"loopback with the console on and no list", func(*Config) {}, nil},
		{"loopback with the console off and no list", func(c *Config) { c.Admin.UIEnabled = false }, nil},
		{"behind a proxy with a list", behindProxy, nil},
		{
			name: "a loopback listener behind a trusted proxy, with no list",
			tune: func(c *Config) {
				behindProxy(c)
				c.Admin.IPAllowList = nil
			},
			refuse: []string{want, remedy, `listener "127.0.0.1:8080", trust_proxy true`},
		},
		{
			name: "the same with the console off, which leaves /admin/v1 served",
			tune: func(c *Config) {
				behindProxy(c)
				c.Admin.IPAllowList = nil
				c.Admin.UIEnabled = false
			},
			refuse: []string{want, remedy, "whether or not admin.ui_enabled is set"},
		},
		{
			name: "every interface with the console off and no list",
			tune: func(c *Config) {
				c.Server.Addr = "0.0.0.0:8080"
				c.Server.AllowPlaintext = true
				c.Admin.UIEnabled = false
			},
			refuse: []string{want, remedy, `listener "0.0.0.0:8080", trust_proxy false`},
		},
		{
			name: "every interface with the console off and a list",
			tune: func(c *Config) {
				c.Server.Addr = "0.0.0.0:8080"
				c.Server.AllowPlaintext = true
				c.Admin.UIEnabled = false
				c.Admin.IPAllowList = []string{"192.0.2.10/32"}
			},
		},
	})
}

// TestServerDeadlinesAndBodyCapMustBeBounded covers the request limits.
//
// net/http reads a zero deadline as none, so each of these would have started
// cleanly and left connections open for as long as a peer cared to hold them.
func TestServerDeadlinesAndBodyCapMustBeBounded(t *testing.T) {
	runRefusals(t, []refusal{
		{"the default", func(*Config) {}, nil},
		{
			name:   "a zero read timeout",
			tune:   func(c *Config) { c.Server.ReadTimeout = Duration{} },
			refuse: []string{"server.read_timeout must be positive, got 0s", `such as "15s"`},
		},
		{
			name:   "a negative read timeout",
			tune:   func(c *Config) { c.Server.ReadTimeout = Duration{-time.Second} },
			refuse: []string{"server.read_timeout must be positive, got -1s"},
		},
		{
			name:   "a zero write timeout",
			tune:   func(c *Config) { c.Server.WriteTimeout = Duration{} },
			refuse: []string{"server.write_timeout must be positive, got 0s", `such as "15s"`},
		},
		{
			name:   "a zero idle timeout",
			tune:   func(c *Config) { c.Server.IdleTimeout = Duration{} },
			refuse: []string{"server.idle_timeout must be positive, got 0s", `such as "60s"`},
		},
		{
			name: "a body cap at the maximum",
			tune: func(c *Config) { c.Server.MaxBodyBytes = MaxRequestBodyBytes },
		},
		{
			name:   "a body cap one byte above the maximum",
			tune:   func(c *Config) { c.Server.MaxBodyBytes = MaxRequestBodyBytes + 1 },
			refuse: []string{"server.max_body_bytes is 16777217, above the maximum of 16777216", "Use the default"},
		},
	})
}

// TestDualApprovalOperationsMustBeOnesTheServiceKnows covers the closed list.
//
// The approval gate compares strings, so a misspelled operation is not held for
// anybody: it goes ahead on one administrator's word while the file reads as
// though a second one were required.
func TestDualApprovalOperationsMustBeOnesTheServiceKnows(t *testing.T) {
	ops := func(names ...string) func(*Config) {
		return func(c *Config) { c.Features.DualApprovalOperations = names }
	}
	runRefusals(t, []refusal{
		{"the default", func(*Config) {}, nil},
		{"a subset of the default", ops("subject.erase"), nil},
		{
			name: "a misspelled operation",
			tune: ops("credential.revoke_bulk", "subject.erasure"),
			refuse: []string{
				`features.dual_approval_operations has no operation "subject.erasure"`,
				"the operations are credential.revoke_bulk, subject.erase, admin_token.create, kek.rotate",
			},
		},
		{
			name:   "an operation in the wrong case",
			tune:   ops("Subject.Erase"),
			refuse: []string{`has no operation "Subject.Erase"`},
		},
		{
			name: "a misspelled operation while dual approval is off",
			tune: func(c *Config) {
				c.Features.DualApproval = false
				c.Features.DualApprovalOperations = []string{"kek.rotation"}
			},
			refuse: []string{`has no operation "kek.rotation"`},
		},
	})
}

// TestDualApprovalOperationNamesMatchTheDefault keeps the closed list and the
// shipped default from drifting apart.
//
// The default holds every operation that has a route, and the closed list is
// every operation that has a route, so they are the same set. One without the
// other is either a default the validator refuses or an operation an operator
// may name that ships switched off without anybody having decided so.
func TestDualApprovalOperationNamesMatchTheDefault(t *testing.T) {
	inDefault := map[string]bool{}
	for _, op := range Default().Features.DualApprovalOperations {
		inDefault[op] = true
	}
	for _, op := range DualApprovalOperationNames {
		if !inDefault[op] {
			t.Errorf("%q is an accepted operation but the default does not hold it", op)
		}
		delete(inDefault, op)
	}
	for op := range inDefault {
		t.Errorf("the default holds %q, which DualApprovalOperationNames does not accept", op)
	}
}

// TestRiskWeightsCannotAllBeZero covers the table that silences the policy.
func TestRiskWeightsCannotAllBeZero(t *testing.T) {
	all := func(weight int) map[string]int {
		out := map[string]int{}
		for _, reason := range RiskReasons {
			out[reason] = weight
		}
		return out
	}
	runRefusals(t, []refusal{
		{"no table at all", func(*Config) {}, nil},
		{
			name: "every reason silenced but one",
			tune: func(c *Config) {
				c.Risk.Weights = all(0)
				c.Risk.Weights["totp_only"] = 1
			},
		},
		{
			name: "every reason but one named and silenced, the last keeping its default",
			tune: func(c *Config) {
				c.Risk.Weights = all(0)
				delete(c.Risk.Weights, "totp_only")
			},
		},
		{
			name: "every reason silenced",
			tune: func(c *Config) { c.Risk.Weights = all(0) },
			refuse: []string{
				"risk.weights sets every reason to 0",
				"give at least one reason a positive weight, or set risk.enabled = false",
			},
		},
		{
			name: "every reason silenced while reporting is off",
			tune: func(c *Config) {
				c.Risk.Enabled = false
				c.Risk.Weights = all(0)
			},
			refuse: []string{"risk.weights sets every reason to 0"},
		},
	})
}

// TestTheSessionCookieIsNeverLeftInsecureOnAnExposedListener pins a property
// rather than a refusal.
//
// No rule refuses admin.session_cookie_secure = false outright, because no
// accepted configuration keeps it: TLS or a declared proxy forces the flag on,
// and a listener that has neither is refused unless server.allow_plaintext is
// set, which is the operator saying in so many words that something else
// constrains the port. This walks the combinations so that a change to either
// rule cannot open the gap between them unnoticed.
func TestTheSessionCookieIsNeverLeftInsecureOnAnExposedListener(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "0.0.0.0:8080", "192.0.2.10:8443"} {
		for _, tls := range []bool{false, true} {
			for _, proxy := range []bool{false, true} {
				for _, plaintext := range []bool{false, true} {
					cfg := validExposedConfig()
					cfg.Server.Addr = addr
					cfg.Server.AllowPlaintext = plaintext
					cfg.Admin.IPAllowList = []string{"10.0.0.0/8"}
					cfg.Admin.SessionCookieSecure = false
					if tls {
						cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "tls.crt", "tls.key"
					}
					if proxy {
						cfg.Server.TrustProxy = true
						cfg.Server.TrustedProxyCIDRs = []string{"10.0.3.0/24"}
					}

					if err := cfg.Validate(); err != nil {
						continue
					}
					exposed := !isLoopbackAddr(addr) || proxy
					if exposed && !cfg.Admin.SessionCookieSecure && !plaintext {
						t.Errorf("addr %s, tls %t, proxy %t: accepted with a session cookie that "+
							"is not Secure and no server.allow_plaintext", addr, tls, proxy)
					}
				}
			}
		}
	}
}

// TestTheDefaultConfigurationStillValidates is the counterpart of every refusal
// above: the defaults, completed with the keys that have none, must load.
func TestTheDefaultConfigurationStillValidates(t *testing.T) {
	cfg := validExposedConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default configuration is refused:\n%v", err)
	}
}

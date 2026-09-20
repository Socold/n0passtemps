package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Socold/n0passtemps/internal/config"
)

// runCheck validates a configuration file.
//
// It is the same validation the service performs at startup, exposed as a
// command so an operator can check a change before restarting. Knowing a
// configuration is wrong is much cheaper before a restart than after.
func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("config", "config.toml", "configuration file to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*path)
	if err != nil {
		return fmt.Errorf("%s is not valid:\n%w", *path, err)
	}

	fmt.Printf("%s is valid.\n\n", *path)
	fmt.Printf("  tenant           %s (%s)\n", cfg.Tenant.ID, cfg.Tenant.Name)
	fmt.Printf("  listener         %s\n", cfg.Server.Addr)
	fmt.Printf("  database         %s\n", cfg.Database.Driver)
	fmt.Printf("  relying party    %s\n", cfg.WebAuthn.RPID)
	fmt.Printf("  origins          %s\n", strings.Join(cfg.WebAuthn.Origins, ", "))
	fmt.Printf("  keyring          %s provider\n", cfg.KEK.Provider)
	fmt.Printf("  lite mode        %t\n", cfg.Features.LiteMode)
	fmt.Printf("  admin interface  %t\n", cfg.Admin.UIEnabled)
	fmt.Printf("  throttling       %t\n", cfg.Throttle.Enabled)

	if cfg.Server.TLSCertFile == "" && !cfg.Server.TrustProxy {
		fmt.Print("\nTLS is not terminated here and no reverse proxy is declared, so this\n" +
			"configuration only validates for a loopback listener.\n")
	}
	return nil
}

// answers is what setup collects.
type answers struct {
	Deployment string // "sqlite" or "postgres"
	RPID       string
	Origin     string
	Addr       string
	TenantName string
	Lite       bool
	AdminUI    bool

	// Exposure says how a listener that is not loopback is protected, and is
	// empty when it is loopback and the question was never asked. One of
	// "tls", "proxy" or "constrained", which are the three the validator
	// accepts. See askExposure.
	Exposure   string
	TLSCert    string
	TLSKey     string
	ProxyCIDRs string

	// AdminAllowList is the networks the administrative surface is reachable
	// from, asked for only when it is served on a listener that is not
	// loopback, whether or not the console is. See askAdminAllowList.
	AdminAllowList string
}

// runSetup asks a short series of questions and writes the files.
//
// The questions are deliberately few. The specification asked for three; this
// asks six, because three cannot cover the relying party identifier, the origin
// and the database choice, and getting any of those wrong produces a failure
// that is hard to trace back to configuration. Everything else takes a default.
func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory to write the generated files into")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return err
	}

	in := bufio.NewReader(os.Stdin)
	var a answers

	fmt.Print("This writes config.toml, docker-compose.yml and .env.\n" +
		"It does not write the keyring or the signing key; those are generated\n" +
		"separately so they can be placed outside the data volume.\n\n")

	lite, err := promptYesNo(in, "Run the lite configuration (SQLite, single administrator, no approval queue)?", true)
	if err != nil {
		return err
	}
	a.Lite = lite
	a.Deployment = "sqlite"
	if !lite {
		var pg bool
		pg, err = promptYesNo(in, "Use PostgreSQL rather than SQLite?", false)
		if err != nil {
			return err
		}
		if pg {
			a.Deployment = "postgres"
		}
	}

	// The relying party identifier is the question operators get wrong most
	// often, so it is asked with its constraint stated rather than left to the
	// validator to reject afterwards.
	fmt.Print("\nThe relying party identifier is a bare domain, not a URL and not a host\n" +
		"with a port. Use \"localhost\" for local development.\n")
	for {
		var v string
		v, err = prompt(in, "Relying party identifier", "localhost")
		if err != nil {
			return err
		}
		a.RPID = v
		if err = probeRPID(v); err != nil {
			fmt.Printf("  %v\n", err)
			continue
		}
		break
	}

	defaultOrigin := "https://" + a.RPID
	if a.RPID == "localhost" {
		defaultOrigin = "http://localhost:8080"
	}
	fmt.Print("\nThe origin is where your front end is served from, scheme and port included.\n" +
		"WebAuthn refuses a ceremony from anywhere else.\n")
	for {
		var v string
		v, err = prompt(in, "Allowed origin", defaultOrigin)
		if err != nil {
			return err
		}
		a.Origin = v
		if err = probeOrigin(v, a.RPID); err != nil {
			fmt.Printf("  %v\n", err)
			continue
		}
		break
	}

	for {
		addr, aerr := prompt(in, "\nListen address", "127.0.0.1:8080")
		if aerr != nil {
			return aerr
		}
		if perr := probeAddr(addr); perr != nil {
			fmt.Printf("  %v\n", perr)
			continue
		}
		a.Addr = addr
		break
	}
	if err = askExposure(in, &a); err != nil {
		return err
	}

	name, err := prompt(in, "Organisation name, shown by the authenticator", "n0passtemps")
	if err != nil {
		return err
	}
	a.TenantName = name

	ui, err := promptYesNo(in, "Serve the administration interface at /admin?", true)
	if err != nil {
		return err
	}
	a.AdminUI = ui
	if err = askAdminAllowList(in, &a); err != nil {
		return err
	}

	// The files are rendered and validated before anything is written, so a
	// rejected configuration does not leave half a deployment on disk.
	cfgBody := renderConfig(a)
	tmp, err := os.CreateTemp("", "n0passtemps-config-*.toml")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	// A removal that fails leaves a temporary file behind and changes nothing
	// about the validation this function performs.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.WriteString(cfgBody); err != nil {
		// The write already failed and the file is removed by the deferred
		// call above, so a close error adds nothing.
		_ = tmp.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	// This close is checked: the file is about to be validated, and a close
	// that failed means the body may not have reached the disk in full, which
	// would surface as a puzzling validation error rather than a write fault.
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}

	// The two secrets are not in the file, so validation is run with them set
	// in this process only.
	probe := map[string]string{
		config.EnvPrefix + "SUBJECT_PEPPER": base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	if a.Deployment == "postgres" {
		// The real connection string lives in .env because it carries a
		// password, so the file on its own has no DSN. Validation is run with
		// the same shape of value the compose file will supply.
		probe[config.EnvPrefix+"DATABASE_DSN"] =
			"postgres://n0passtemps:placeholder@postgres:5432/n0passtemps?sslmode=disable"
		probe[config.EnvPrefix+"DATABASE_ALLOW_PLAINTEXT"] = "true"
	}
	restore := withTemporaryEnv(probe)
	_, verr := config.Load(tmpName)
	restore()
	if verr != nil {
		return fmt.Errorf("the generated configuration does not validate, which is a bug "+
			"in this tool rather than in your answers:\n%w", verr)
	}

	files := map[string]struct {
		body string
		mode os.FileMode
	}{
		"config.toml":        {cfgBody, 0o640},
		"docker-compose.yml": {renderCompose(a), 0o644},
		".env":               {renderEnv(a), 0o600},
	}
	for name, f := range files {
		path := *dir + "/" + name
		if err := writeFile(path, []byte(f.body), f.mode, *force); err != nil {
			return err
		}
		fmt.Printf("Wrote %s\n", path)
	}

	const image = "ghcr.io/socold/n0passtemps:1.1.3"
	const wizard = "--entrypoint /usr/local/bin/n0passtemps-wizard " + image
	const mount = "-v n0passtemps_n0passtemps-kek:/etc/n0passtemps/kek"

	fmt.Print("\nFour steps remain, and none of them can be done for you.\n\n" +
		"  1. Create the keyring and the signing key inside the secrets volume. They are\n" +
		"     generated by the image itself, so they never exist on this host:\n\n" +
		"       docker volume create n0passtemps_n0passtemps-kek\n" +
		"       docker run --rm " + mount + " " + wizard + " \\\n" +
		"         kek init -out /etc/n0passtemps/kek/keyring.json\n" +
		"       docker run --rm " + mount + " " + wizard + " \\\n" +
		"         assertion-key init -out /etc/n0passtemps/kek/assertion-key.pem\n\n" +
		"  2. Generate the subject pepper and put the value in .env:\n\n" +
		"       docker run --rm " + wizard + " pepper\n\n" +
		"  3. Start it:\n\n" +
		"       docker compose up -d\n\n" +
		"  4. Create the first administrator" + quorumWording(a) + ":\n\n" +
		"       docker compose run --rm n0passtemps -bootstrap-admin" + adminsFlag(a) + "\n\n" +
		"     The tokens are printed once, to your terminal and nowhere else. They are\n" +
		"     deliberately not printed by the running service, whose output goes to a\n" +
		"     log pipeline.\n\n" +
		"Back up the secrets volume and the pepper now. Losing the pepper makes every\n" +
		"existing user unfindable; losing the keyring makes the TOTP secrets unreadable.\n")
	return nil
}

// askAdminAllowList asks who may reach the administrative surface, when it is
// served somewhere an allow list is required.
//
// The condition is the validator's: the administrative surface on a listener
// that is not loopback, with no allow list, is refused. It does not depend on
// the console. Saying no to the console turns off the pages and leaves
// /admin/v1 on the same port, answering a bearer token from anywhere. This had the same shape
// of failure askExposure fixes -- the list was written into the file as a
// commented example, so the run ended on "this is a bug in this tool" for
// anybody who said yes to the console on a listener they had also been allowed
// to set to anything.
func askAdminAllowList(in *bufio.Reader, a *answers) error {
	if !listenerNeedsExposure(a.Addr) {
		return nil
	}

	fmt.Print("\nThe administrative routes would be reachable from every network that\n" +
		"can reach the service, so it needs an allow list. A container published to\n" +
		"127.0.0.1, which is what the generated compose file does, is reached from\n" +
		"the host itself.\n\n")

	for {
		list, err := prompt(in, "Networks administration is reachable from, comma separated", "127.0.0.1/32")
		if err != nil {
			return err
		}
		if perr := probeAdminAllowList(list); perr != nil {
			fmt.Printf("  %v\n", perr)
			continue
		}
		a.AdminAllowList = list
		return nil
	}
}

// probeAdminAllowList reproduces the CIDR rules for the console's list.
func probeAdminAllowList(list string) error {
	cfg := config.Default()
	cfg.Admin.IPAllowList = splitCIDRs(list)
	if len(cfg.Admin.IPAllowList) == 0 {
		return errors.New("at least one network is required")
	}
	return firstRelevantError(cfg.Validate(), "ip_allow_list")
}

// probeAddr reproduces the listener's shape rules, so a malformed address is
// re-asked rather than failing the whole run at the end.
//
// It probes with allow_plaintext set, because the plaintext rule is a separate
// question askExposure puts to the operator; this one is only about whether the
// string is an address at all.
func probeAddr(addr string) error {
	cfg := config.Default()
	cfg.Server.Addr = addr
	cfg.Server.AllowPlaintext = true
	return firstRelevantError(cfg.Validate(), "server.addr")
}

// listenerNeedsExposure reports whether the address obliges the operator to say
// how TLS is accounted for.
//
// The rule is the validator's rather than a copy of it: an address that
// validates with allow_plaintext and fails without it is exactly one the
// service will not serve in clear, which is the set askExposure exists for. A
// malformed address fails both and is caught by probeAddr first.
func listenerNeedsExposure(addr string) bool {
	cfg := config.Default()
	cfg.Server.Addr = addr
	cfg.Server.AllowPlaintext = true
	if firstRelevantError(cfg.Validate(), "server.addr") != nil {
		return false
	}
	cfg.Server.AllowPlaintext = false
	return firstRelevantError(cfg.Validate(), "server.addr") != nil
}

// askExposure puts the one question a non-loopback listener cannot be set up
// without.
//
// It is conditional, like the PostgreSQL question, so the common answer of
// 127.0.0.1:8080 still walks the six questions the tool promises. Before it
// existed, answering 0.0.0.0:8080 -- the obvious answer for a container, and
// the one the generated compose file publishes behind -- produced a file that
// the service refuses, so the run ended on "this is a bug in this tool" and
// wrote nothing at all. An operator with no support channel was left with the
// tool blaming itself and no files.
//
// The three choices are the three the validator names in its own message, in
// the order an operator is likely to want them.
func askExposure(in *bufio.Reader, a *answers) error {
	if !listenerNeedsExposure(a.Addr) {
		return nil
	}

	fmt.Printf("\n%s is not loopback, so every credential would cross the network\n"+
		"in clear unless something accounts for TLS. Three arrangements are accepted.\n\n"+
		"  1. This process terminates TLS.\n"+
		"  2. A reverse proxy in front terminates it.\n"+
		"  3. Something outside already constrains who can reach the port, such as a\n"+
		"     container published to loopback, which is what the generated compose\n"+
		"     file does.\n\n", a.Addr)

	for {
		choice, err := prompt(in, "Which one", "3")
		if err != nil {
			return err
		}
		switch strings.TrimSpace(choice) {
		case "1":
			a.Exposure = "tls"
			if a.TLSCert, err = prompt(in, "Certificate chain path",
				"/etc/n0passtemps/tls/fullchain.pem"); err != nil {
				return err
			}
			if a.TLSKey, err = prompt(in, "Private key path",
				"/etc/n0passtemps/tls/privkey.pem"); err != nil {
				return err
			}
			return nil
		case "2":
			a.Exposure = "proxy"
			// The networks are asked for rather than defaulted, because
			// trusting a forwarded address from anywhere lets a caller choose
			// the address rate limiting and audit entries are keyed on.
			for {
				cidrs, cerr := prompt(in, "Networks the proxy speaks from, comma separated", "10.0.0.0/8")
				if cerr != nil {
					return cerr
				}
				if perr := probeProxyCIDRs(cidrs); perr != nil {
					fmt.Printf("  %v\n", perr)
					continue
				}
				a.ProxyCIDRs = cidrs
				return nil
			}
		case "3":
			a.Exposure = "constrained"
			return nil
		default:
			fmt.Print("  Answer 1, 2 or 3.\n")
		}
	}
}

// probeProxyCIDRs reproduces the CIDR rules, so a typo is re-asked.
func probeProxyCIDRs(list string) error {
	cfg := config.Default()
	cfg.Server.TrustProxy = true
	cfg.Server.TrustedProxyCIDRs = splitCIDRs(list)
	if len(cfg.Server.TrustedProxyCIDRs) == 0 {
		return errors.New("at least one network is required")
	}
	return firstRelevantError(cfg.Validate(), "trusted_proxy_cidrs")
}

// splitCIDRs turns the comma separated answer into the list the config holds.
func splitCIDRs(list string) []string {
	var out []string
	for _, part := range strings.Split(list, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// withTemporaryEnv sets variables and returns a function restoring them.
func withTemporaryEnv(vars map[string]string) func() {
	previous := make(map[string]*string, len(vars))
	for k, v := range vars {
		if old, ok := os.LookupEnv(k); ok {
			previous[k] = &old
		} else {
			previous[k] = nil
		}
		_ = os.Setenv(k, v)
	}
	return func() {
		for k, old := range previous {
			if old == nil {
				_ = os.Unsetenv(k)
				continue
			}
			_ = os.Setenv(k, *old)
		}
	}
}

// probeRPID reproduces the validator's relying party rules, so the question can
// be re-asked instead of the whole run failing at the end.
func probeRPID(v string) error {
	cfg := config.Default()
	cfg.WebAuthn.RPID = v
	cfg.WebAuthn.Origins = []string{"https://" + v}
	if v == "localhost" {
		cfg.WebAuthn.Origins = []string{"http://localhost:8080"}
	}
	return firstRelevantError(cfg.Validate(), "rp_id")
}

// probeOrigin reproduces the origin rules, including that the origin has to be
// covered by the relying party identifier.
func probeOrigin(origin, rpID string) error {
	cfg := config.Default()
	cfg.WebAuthn.RPID = rpID
	cfg.WebAuthn.Origins = []string{origin}
	return firstRelevantError(cfg.Validate(), "origins")
}

// firstRelevantError pulls the one message about a field out of the joined
// validation error, so the prompt shows the relevant line rather than every
// unrelated complaint about a configuration that is still half built.
func firstRelevantError(err error, field string) error {
	if err == nil {
		return nil
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		if strings.Contains(line, field) {
			return fmt.Errorf("%s", strings.TrimSpace(line))
		}
	}
	return nil
}

// adminsFlag asks for two initial administrators whenever approvals are on.
//
// With dual approval, minting an administrator through the API needs a second
// administrator to approve it, so a deployment that starts with one can never
// create another. The quorum has to be created together.
func adminsFlag(a answers) string {
	if a.Lite {
		return ""
	}
	return " -admins 2"
}

func quorumWording(a answers) string {
	if a.Lite {
		return ""
	}
	return "s. Two, because with dual approval on a single\n     administrator cannot mint a second through the API"
}

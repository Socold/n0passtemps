package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/health"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/subject"
	"github.com/Socold/n0passtemps/internal/throttle"

	adminui "github.com/Socold/n0passtemps/internal/admin/ui"
)

// keyring is what a provider has to satisfy to serve both the sealer and the
// health report.
//
// The two consumers need different subsets: the sealer needs to fetch a key by
// version in order to read a record sealed under an older one, while the health
// report only needs to know which versions exist. Declaring the union here,
// where both are used, keeps each package's own interface as narrow as it can
// be.
type keyring interface {
	envelope.KEKProvider
	health.KeyringInspector
}

// keyringAnchor estimates when the current key version became current.
//
// The keyring file records no history, so there is nothing authoritative to
// read. The oldest audit entry is used as a lower bound: the current key cannot
// have been in use for longer than the database has existed. An operator who
// rotates without the service restarting will see the reminder fire early,
// which is the safe direction to be wrong in, and the reminder is advisory
// rather than a refusal.
func keyringAnchor(ctx context.Context, cfg *config.Config, st store.Store, log *slog.Logger) time.Time {
	entries, err := st.QueryAudit(ctx, cfg.TenantID(), store.AuditFilter{Limit: 1})
	if err != nil || len(entries) == 0 {
		// A fresh database, or a query that failed. Anchoring on now means
		// rotation is not reported as overdue on a new deployment.
		if err != nil {
			log.DebugContext(ctx, "keyring age not determined from the audit log",
				slog.Any("error", err))
		}
		return time.Now().UTC()
	}
	return entries[0].OccurredAt
}

// mintBootstrapToken creates the first administrative credential.
//
// The returned string is the only time the token exists in retrievable form.
// Only its selector and a digest of its verifier are stored.
func mintBootstrapToken(ctx context.Context, cfg *config.Config, st store.Store, name string) (string, *store.AdminToken, error) {
	tok, err := token.Generate(token.KindAdmin)
	if err != nil {
		return "", nil, fmt.Errorf("generate bootstrap token: %w", err)
	}

	now := time.Now().UTC()
	admin := &store.AdminToken{
		ID:           uuid.NewString(),
		TenantID:     cfg.TenantID(),
		Name:         name,
		Selector:     tok.Selector,
		VerifierHash: tok.Hash,
		Role:         store.RoleFull,
		CreatedAt:    now,
		CreatedBy:    "system:bootstrap",
	}
	if err := st.CreateAdminToken(ctx, admin); err != nil {
		return "", nil, fmt.Errorf("store bootstrap token: %w", err)
	}
	return tok.Display, admin, nil
}

// buildAdminUI constructs the administration interface, or returns nil when it
// is disabled.
//
// Returning nil rather than a handler that refuses every request means the
// routes are never registered at all, so a disabled interface presents no
// surface to probe.
func buildAdminUI(cfg *config.Config, st store.Store, rec *audit.Recorder, subjects *subject.Service, limiter *throttle.Limiter, log *slog.Logger) (*adminui.Handler, error) {
	if !cfg.Admin.UIEnabled {
		log.Info("administration interface disabled by configuration")
		return nil, nil
	}
	return adminui.New(adminui.Deps{
		Config:   cfg,
		Store:    st,
		Recorder: rec,
		Subjects: subjects,
		Limiter:  limiter,
		Logger:   log,
		Clock:    time.Now,
	})
}

// maxBootstrapAdmins bounds -admins. The command exists to establish a quorum,
// not to provision a team; everyone after the quorum is minted through the API,
// where the action is attributed to a named administrator.
const maxBootstrapAdmins = 5

// bootstrapAdmin creates the initial administrative tokens and prints them.
//
// It is a separate invocation of the binary rather than something the service
// does on its first start, and the distinction matters. A long-running service
// writes to a log stream, and log streams are shipped, indexed and retained by
// systems whose access rules are looser than those of a credential store. A
// token printed there is a token stored in clear somewhere nobody is watching.
// A one-shot command writes to the terminal of the operator who ran it and to
// nothing else.
//
// # Why it can create more than one
//
// With dual approval on, minting an administrative token through the API is
// held for a second administrator. A deployment with exactly one administrator
// therefore cannot create its second: nobody exists to approve the request.
//
// The tempting fix is an exemption in the API: let a sole administrator mint
// without approval. That exemption is reachable by an attacker. One rogue
// administrator revokes the others, becomes the sole administrator, mints a
// token they control, and from then on approves their own requests; the
// two-person rule is gone. So the API keeps no exemption at all, and the
// initial quorum is created here instead, by whoever can run this command.
// That person already holds the configuration, the keyring and the database,
// so the ability grants them nothing they did not have.
//
// It refuses when a usable full administrator already exists, unless -force is
// given, for the operator who has lost every token. The audit entry records
// that the path was used.
func bootstrapAdmin(ctx context.Context, cfg *config.Config, st store.Store, rec *audit.Recorder, force bool, n int) error {
	if n < 1 || n > maxBootstrapAdmins {
		return fmt.Errorf("-admins must be between 1 and %d, got %d", maxBootstrapAdmins, n)
	}

	count, err := st.CountAdminTokensByRole(ctx, cfg.TenantID(), store.RoleFull)
	if err != nil {
		return fmt.Errorf("count administrators: %w", err)
	}
	if count > 0 && !force {
		return fmt.Errorf("%d usable full administrator token(s) already exist; mint further "+
			"tokens through POST /admin/v1/admin-tokens, or pass -force if every token "+
			"has been lost", count)
	}

	fmt.Fprintln(os.Stdout)
	for i := 1; i <= n; i++ {
		display, admin, err := mintBootstrapToken(ctx, cfg, st, fmt.Sprintf("bootstrap-%d", i))
		if err != nil {
			return err
		}
		if err := rec.Success(ctx, audit.Event{
			TenantID:     cfg.TenantID(),
			EventType:    audit.EventAdminTokenCreated,
			ActorType:    store.ActorSystem,
			ResourceType: "admin_token",
			ResourceID:   admin.ID,
			Detail: map[string]any{
				"bootstrap": true,
				"forced":    force && count > 0,
				"role":      string(store.RoleFull),
				"name":      admin.Name,
			},
		}); err != nil {
			return fmt.Errorf("audit bootstrap administrator: %w", err)
		}
		fmt.Fprintf(os.Stdout, "%s  %s\n", admin.Name, display)
	}
	fmt.Fprintln(os.Stdout)

	fmt.Fprint(os.Stderr,
		"Each token is shown once. Only a digest is stored, so none can be displayed\n"+
			"again. Put them in a password manager now, one per person.\n\n"+
			"Use a token as a bearer credential against /admin/v1, or paste it into the\n"+
			"sign-in page at /admin. Then mint a named token per administrator through\n"+
			"POST /admin/v1/admin-tokens and revoke these.\n\n")

	if cfg.Features.DualApproval && count+n < 2 {
		fmt.Fprint(os.Stderr,
			"Dual approval is on and this deployment now has a single administrator.\n"+
				"Minting another through the API needs a second administrator to approve it,\n"+
				"and there is none. Run this command again with -force -admins 1, or start\n"+
				"over with -admins 2, and give the second token to a different person.\n\n")
	}
	return nil
}

// warnIfNoAdministrator tells an operator how to get in on a fresh deployment.
func warnIfNoAdministrator(ctx context.Context, cfg *config.Config, st store.Store, log *slog.Logger) {
	count, err := st.CountAdminTokensByRole(ctx, cfg.TenantID(), store.RoleFull)
	if err != nil || count > 0 {
		return
	}
	hint := "n0passtemps-server -config <path> -bootstrap-admin"
	if cfg.Features.DualApproval {
		// One administrator cannot mint a second while approvals are on, so
		// the quorum has to be created together.
		hint += " -admins 2"
	}
	log.WarnContext(ctx, "no administrator exists yet; create the first with: "+hint)
}

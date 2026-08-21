package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type fakeHarbor struct {
	server        *httptest.Server
	created       []robotRequest
	deleted       []string
	existing      []robotResponse
	refreshed     map[string]string
	refuseRefresh bool
	nextID        int
}

func newFakeHarbor(t *testing.T) *fakeHarbor {
	t.Helper()
	f := &fakeHarbor{refreshed: map[string]string{}, nextID: 42}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2.0/robots", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(f.existing)
			return
		}
		var req robotRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.created = append(f.created, req)
		id := f.nextID
		f.nextID++
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(robotResponse{
			ID:     id,
			Name:   "robot$" + req.Name,
			Secret: fmt.Sprintf("s3cret-%d", id),
		})
	})
	mux.HandleFunc("/api/v2.0/robots/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v2.0/robots/")
		switch r.Method {
		case http.MethodDelete:
			f.deleted = append(f.deleted, id)
			w.WriteHeader(http.StatusOK)
		case http.MethodPatch:
			if f.refuseRefresh {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var body struct {
				Secret string `json:"secret"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.refreshed[id] = body.Secret
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func configured(t *testing.T, url string) (*harborBackend, logical.Storage) {
	t.Helper()
	config := &logical.BackendConfig{StorageView: &logical.InmemStorage{}}
	b := backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   config.StorageView,
		Data: map[string]any{
			"url":      url,
			"username": "admin",
			"password": "password",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("configuring failed: %v %v", err, resp)
	}
	return b, config.StorageView
}

func writeRole(t *testing.T, b *harborBackend, s logical.Storage, name string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Storage:   s,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("writing the role failed: %v", err)
	}
	return resp
}

func TestIssuedRobotIsScopedToTheRoleAndDeletedWhenTheLeaseEnds(t *testing.T) {
	fake := newFakeHarbor(t)
	b, storage := configured(t, fake.server.URL)
	writeRole(t, b, storage, "ci", map[string]any{"project": "library", "push": true})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/ci",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if resp.Data["secret"] != "s3cret-42" {
		t.Fatalf("expected the robot secret, got %v", resp.Data["secret"])
	}
	if got := fake.created[0].Permissions[0].Namespace; got != "library" {
		t.Fatalf("robot was scoped to %q, expected the project from the role", got)
	}
	if got := fake.created[0].Level; got != "project" {
		t.Fatalf("robot was created at level %q, expected project", got)
	}
	if got := fake.created[0].Permissions[0].Kind; got != "project" {
		t.Fatalf("permission kind was %q, expected the grant to stay confined to a project", got)
	}
	if len(fake.created[0].Permissions[0].Access) != 2 {
		t.Fatal("the role grants push but only one access rule was sent")
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/ci",
		Storage:   storage,
		Secret:    resp.Secret,
	}); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != "42" {
		t.Fatalf("expected robot 42 to be deleted, deleted %v", fake.deleted)
	}
}

func TestALeaseCannotOutliveTheRobot(t *testing.T) {
	fake := newFakeHarbor(t)
	b, storage := configured(t, fake.server.URL)
	writeRole(t, b, storage, "ci", map[string]any{"project": "library"})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/ci",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if resp.Secret.MaxTTL > maxRobotLifetime {
		t.Fatalf("lease may live %s but the robot only lives %s", resp.Secret.MaxTTL, maxRobotLifetime)
	}
	if robotLife := time.Duration(robotExpiryDays) * 24 * time.Hour; resp.Secret.MaxTTL >= robotLife {
		t.Fatalf("lease max %s leaves no margin before the robot expires at %s", resp.Secret.MaxTTL, robotLife)
	}
}

func TestARoleCannotAskForMoreThanTheRobotLives(t *testing.T) {
	fake := newFakeHarbor(t)
	b, storage := configured(t, fake.server.URL)

	resp := writeRole(t, b, storage, "greedy", map[string]any{
		"project": "library",
		"max_ttl": int((maxRobotLifetime + time.Hour).Seconds()),
	})
	if resp == nil || !resp.IsError() {
		t.Fatal("a role outliving the robot should be refused")
	}
}

func TestIssuingWithoutARoleIsRefused(t *testing.T) {
	fake := newFakeHarbor(t)
	b, storage := configured(t, fake.server.URL)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/missing",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("expected a refusal, got an error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("issuing for an unknown role should be refused")
	}
	if len(fake.created) != 0 {
		t.Fatal("nothing should have been created in harbor")
	}
}

func TestIssuingWithoutConfigIsRefused(t *testing.T) {
	config := &logical.BackendConfig{StorageView: &logical.InmemStorage{}}
	b := backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	entry, err := logical.StorageEntryJSON(rolesStoragePrefix+"ci", &harborRole{Project: "library"})
	if err != nil {
		t.Fatal(err)
	}
	if err := config.StorageView.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/ci",
		Storage:   config.StorageView,
	})
	if err != nil {
		t.Fatalf("expected a refusal, got an error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("issuing without configuration should be refused")
	}
}

func TestAnInterruptedCreateIsBoundedByTheAccountExpiry(t *testing.T) {
	fake := newFakeHarbor(t)
	b, storage := configured(t, fake.server.URL)
	writeRole(t, b, storage, "ci", map[string]any{"project": "library"})

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/ci",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

	if got := fake.created[0].Duration; got != robotExpiryDays {
		t.Fatalf("account expiry is %d days; an account vault loses track of relies on it", got)
	}
	if robotExpiryDays < 1 {
		t.Fatal("an account with no expiry of its own would be left behind forever")
	}
}

func rotate(t *testing.T, b *harborBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	})
}

func TestRotatingRootReplacesTheSecretInHarborAndInStorage(t *testing.T) {
	f := newFakeHarbor(t)
	f.existing = []robotResponse{{ID: 7, Name: "admin"}}
	b, s := configured(t, f.server.URL)

	if resp, err := rotate(t, b, s); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotating failed: %v %v", err, resp)
	}

	stored, err := getConfig(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Password == "password" {
		t.Fatal("the old secret is still in storage")
	}
	if len(stored.Password) != rootSecretLength {
		t.Fatalf("stored secret is %d characters, want %d", len(stored.Password), rootSecretLength)
	}
	if f.refreshed["7"] != stored.Password {
		t.Fatalf("harbor got %q but storage holds %q", f.refreshed["7"], stored.Password)
	}
}

func TestARefusedRotationLeavesTheOldSecretUsable(t *testing.T) {
	f := newFakeHarbor(t)
	f.existing = []robotResponse{{ID: 7, Name: "admin"}}
	b, s := configured(t, f.server.URL)
	f.refuseRefresh = true

	if _, err := rotate(t, b, s); err == nil {
		t.Fatal("a refused rotation should report an error")
	}

	stored, err := getConfig(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Password != "password" {
		t.Fatalf("the old secret was not put back, storage holds %q", stored.Password)
	}
}

func TestRotatingFindsARobotByItsPrefixedName(t *testing.T) {
	f := newFakeHarbor(t)
	f.existing = []robotResponse{{ID: 3, Name: "someone-else"}, {ID: 9, Name: "stronghold"}}

	config := &logical.BackendConfig{StorageView: &logical.InmemStorage{}}
	b := backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   config.StorageView,
		Data: map[string]any{
			"url":      f.server.URL,
			"username": "robot$stronghold",
			"password": "password",
		},
	}); err != nil {
		t.Fatal(err)
	}

	if resp, err := rotate(t, b, config.StorageView); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotating failed: %v %v", err, resp)
	}
	if _, ok := f.refreshed["9"]; !ok {
		t.Fatalf("harbor refreshed %v, want robot 9", f.refreshed)
	}
}

func TestRotatingWithoutConfigIsRefused(t *testing.T) {
	config := &logical.BackendConfig{StorageView: &logical.InmemStorage{}}
	b := backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	resp, err := rotate(t, b, config.StorageView)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected a refusal, got %v", resp)
	}
}

func TestGeneratedSecretsCarryEveryClassHarborDemands(t *testing.T) {
	for range 200 {
		secret, err := generateSecret()
		if err != nil {
			t.Fatal(err)
		}
		if len(secret) != rootSecretLength {
			t.Fatalf("got %d characters, want %d", len(secret), rootSecretLength)
		}
		if !strings.ContainsAny(secret, lowers) || !strings.ContainsAny(secret, uppers) || !strings.ContainsAny(secret, digits) {
			t.Fatalf("secret %q is missing a character class", secret)
		}
	}
}

func write(t *testing.T, b *harborBackend, s logical.Storage, path string, data map[string]any) *logical.Response {
	t.Helper()
	for _, op := range []logical.Operation{logical.UpdateOperation, logical.CreateOperation} {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: op, Path: path, Storage: s, Data: data,
		})
		if err != nil && strings.Contains(err.Error(), "unsupported operation") {
			continue
		}
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("writing %s failed: %v %v", path, err, resp)
		}
		return resp
	}
	t.Fatalf("no write operation accepted for %s", path)
	return nil
}

func read(t *testing.T, b *harborBackend, s logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: path, Storage: s,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("reading %s failed: %v %v", path, err, resp)
	}
	return resp
}

func harborStaticFixture(t *testing.T, b *harborBackend, s logical.Storage, data map[string]any) {
	t.Helper()
	base := map[string]any{"project": "clique"}
	for k, v := range data {
		base[k] = v
	}
	write(t, b, s, "static-roles/pull", base)
}

func agedHarborStaticRole(t *testing.T, s logical.Storage, name string, since time.Duration) {
	t.Helper()
	role, err := getStaticRole(context.Background(), s, name)
	if err != nil || role == nil {
		t.Fatalf("static role %q is missing: %v", name, err)
	}
	role.LastRotation = time.Now().Add(-since)
	if err := storeStaticRole(context.Background(), s, name, role); err != nil {
		t.Fatal(err)
	}
}

func TestAStaticRoleHandsOutOneAccountToEveryReader(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := configured(t, f.server.URL)
	harborStaticFixture(t, b, s, nil)

	first := read(t, b, s, "static-creds/pull")
	second := read(t, b, s, "static-creds/pull")

	if first.Data["name"] != second.Data["name"] || first.Data["secret"] != second.Data["secret"] {
		t.Fatalf("every reader must get the same account, got %v then %v", first.Data, second.Data)
	}
	if len(f.created) != 1 {
		t.Fatalf("reading must not create accounts, harbor made %d", len(f.created))
	}
}

func TestRotatingAStaticRoleReplacesTheAccount(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := configured(t, f.server.URL)
	harborStaticFixture(t, b, s, nil)

	before := read(t, b, s, "static-creds/pull")
	write(t, b, s, "rotate-role/pull", map[string]any{})
	after := read(t, b, s, "static-creds/pull")

	if before.Data["name"] == after.Data["name"] {
		t.Fatal("rotation must produce a different account")
	}
	if before.Data["secret"] == after.Data["secret"] {
		t.Fatal("rotation must produce a different secret")
	}
	if len(f.deleted) != 1 || f.deleted[0] != "42" {
		t.Fatalf("the previous account must be deleted, deleted=%v", f.deleted)
	}
}

func TestAStaticRoleWithoutAPeriodNeverRotatesItself(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := configured(t, f.server.URL)
	harborStaticFixture(t, b, s, nil)

	before := read(t, b, s, "static-creds/pull").Data["name"]
	agedHarborStaticRole(t, s, "pull", 365*24*time.Hour)

	if err := b.rotateDueStaticRoles(context.Background(), &logical.Request{Storage: s}); err != nil {
		t.Fatal(err)
	}
	if read(t, b, s, "static-creds/pull").Data["name"] != before {
		t.Fatal("a role without a rotation period must never rotate on its own, however old it is")
	}
}

func TestTheScheduleRotatesAHarborRoleThatIsDue(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := configured(t, f.server.URL)
	harborStaticFixture(t, b, s, map[string]any{"rotation_period": 3600})

	before := read(t, b, s, "static-creds/pull").Data["name"]
	agedHarborStaticRole(t, s, "pull", 2*time.Hour)

	if err := b.rotateDueStaticRoles(context.Background(), &logical.Request{Storage: s}); err != nil {
		t.Fatal(err)
	}
	if read(t, b, s, "static-creds/pull").Data["name"] == before {
		t.Fatal("a role past its rotation period must be rotated")
	}
	if len(f.deleted) != 1 {
		t.Fatalf("the previous account must be deleted, deleted=%v", f.deleted)
	}
}

func TestHarborExpiryStaysClearOfTheRotationSchedule(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := configured(t, f.server.URL)

	harborStaticFixture(t, b, s, map[string]any{"rotation_period": 30 * 24 * 3600})
	if got := f.created[0].Duration; got != 37 {
		t.Fatalf("a thirty day rotation needs a longer expiry, got %d days", got)
	}

	write(t, b, s, "static-roles/manual", map[string]any{"project": "clique"})
	if got := f.created[1].Duration; got != robotNeverExpires {
		t.Fatalf("a role nothing rotates must not expire on its own, got %d", got)
	}
}

func TestAStaticRoleCannotTakeARoleName(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := configured(t, f.server.URL)
	writeRole(t, b, s, "ci", map[string]any{"project": "clique"})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/ci",
		Storage:   s,
		Data:      map[string]any{"project": "clique"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("sharing a name with a role must be refused, got %v", resp)
	}
}

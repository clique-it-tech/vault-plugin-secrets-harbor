package harbor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type fakeHarbor struct {
	server   *httptest.Server
	created  []robotRequest
	deleted  []string
	existing []robotResponse
}

func newFakeHarbor(t *testing.T) *fakeHarbor {
	t.Helper()
	f := &fakeHarbor{}

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
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(robotResponse{ID: 42, Name: "robot$" + req.Name, Secret: "s3cret"})
	})
	mux.HandleFunc("/api/v2.0/robots/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/api/v2.0/robots/"))
		w.WriteHeader(http.StatusOK)
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
	if resp.Data["secret"] != "s3cret" {
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

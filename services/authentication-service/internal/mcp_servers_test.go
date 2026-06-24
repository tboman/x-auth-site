package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMemMCPServerCRUD(t *testing.T) {
	store := NewMemStorage()
	m := MCPServer{ID: "mcp_1", TenantID: "ten_acme", Name: "Acme CRM", ResourceURI: "https://mcp.acme.com", Scopes: []string{"crm.read"}, Enabled: true}
	if err := store.CreateMCPServer(m); err != nil {
		t.Fatalf("CreateMCPServer: %v", err)
	}

	// Duplicate (tenant, resource_uri) conflicts even with a different id.
	dup := m
	dup.ID = "mcp_2"
	if err := store.CreateMCPServer(dup); err != ErrConflict {
		t.Errorf("duplicate resource_uri: got %v, want ErrConflict", err)
	}
	// Same resource_uri in a different tenant is fine.
	other := m
	other.ID, other.TenantID = "mcp_3", "ten_other"
	if err := store.CreateMCPServer(other); err != nil {
		t.Errorf("same resource_uri, different tenant: %v", err)
	}

	list, _ := store.ListMCPServers("ten_acme")
	if len(list) != 1 || list[0].ResourceURI != "https://mcp.acme.com" {
		t.Fatalf("ListMCPServers(ten_acme) = %+v, want one Acme server", list)
	}

	got, err := store.GetMCPServer("ten_acme", "mcp_1")
	if err != nil || !got.Enabled || len(got.Scopes) != 1 {
		t.Fatalf("GetMCPServer = %+v, err %v", got, err)
	}
	// Tenant isolation on get.
	if _, err := store.GetMCPServer("ten_other", "mcp_1"); err != ErrNotFound {
		t.Errorf("cross-tenant get: got %v, want ErrNotFound", err)
	}

	if err := store.SetMCPServerEnabled("ten_acme", "mcp_1", false); err != nil {
		t.Fatalf("SetMCPServerEnabled: %v", err)
	}
	got, _ = store.GetMCPServer("ten_acme", "mcp_1")
	if got.Enabled {
		t.Errorf("server should be disabled after toggle")
	}

	if err := store.DeleteMCPServer("ten_acme", "mcp_1"); err != nil {
		t.Fatalf("DeleteMCPServer: %v", err)
	}
	if _, err := store.GetMCPServer("ten_acme", "mcp_1"); err != ErrNotFound {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestDiscoveryAdvertisesTokenExchange(t *testing.T) {
	// supportedGrantTypes carries the XAA/ID-JAG token-exchange grant.
	found := false
	for _, g := range supportedGrantTypes() {
		if g == GrantTypeTokenExchange {
			found = true
		}
	}
	if !found {
		t.Fatalf("supportedGrantTypes missing %q", GrantTypeTokenExchange)
	}

	// And both discovery documents serve it.
	h := &OIDCHandlers{Issuer: "http://test.local"}
	for _, tc := range []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"oauth", h.OAuthMetadata},
		{"oidc", h.OIDCMetadata},
	} {
		rec := httptest.NewRecorder()
		tc.fn(rec, httptest.NewRequest(http.MethodGet, "/.well-known/x", nil))
		var doc struct {
			GrantTypes []string `json:"grant_types_supported"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		has := false
		for _, g := range doc.GrantTypes {
			if g == GrantTypeTokenExchange {
				has = true
			}
		}
		if !has {
			t.Errorf("%s metadata grant_types_supported = %v, missing token-exchange", tc.name, doc.GrantTypes)
		}
	}
}

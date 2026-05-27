// Package bonbontest stands up an in-memory HTTP fake of the AWS Account
// Access Manager API (codename: Bonbon). It accepts any signed request — the
// SigV4 code path in the production client is exercised end-to-end by going
// through Client.do(), but the server itself does not validate signatures.
// The seed graph is documented at the top of NewTestServer and matches the
// expectations in connector_test.go.
package bonbontest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/conductorone/baton-aws/pkg/connector/bonbon"
)

const (
	testAppArn = "arn:aws:account-access:us-east-1:123456789012:application/app-bonbon-1"
	testRole1  = "arn:aws:iam::123456789012:role/BonbonRoleAlpha"
	testRole2  = "arn:aws:iam::123456789012:role/BonbonRoleBeta"

	UserId1  = "11111111-aaaa-bbbb-cccc-111111111111"
	UserId2  = "22222222-aaaa-bbbb-cccc-222222222222"
	UserId3  = "33333333-aaaa-bbbb-cccc-333333333333"
	GroupId1 = "44444444-dddd-eeee-ffff-444444444444"
	GroupId2 = "55555555-dddd-eeee-ffff-555555555555"
)

// TestAppArn / TestRoles are the canonical seed identifiers tests assert against.
func TestAppArn() string     { return testAppArn }
func TestRoleArns() []string { return []string{testRole1, testRole2} }

// Server is the test fake. Use New() to construct one with the default seed
// graph, then call URL() for the base URL to pass into bonbon.NewClient.
type Server struct {
	mu sync.Mutex

	httpServer *httptest.Server

	applications map[string]bonbon.Application
	entitlements map[string]map[string]bonbon.EntitlementSummary

	idSeq int
}

func New() *Server {
	s := &Server{
		applications: map[string]bonbon.Application{},
		entitlements: map[string]map[string]bonbon.EntitlementSummary{},
	}
	s.seed()
	s.httpServer = httptest.NewServer(http.HandlerFunc(s.route))
	return s
}

func (s *Server) Close()         { s.httpServer.Close() }
func (s *Server) URL() string    { return s.httpServer.URL }
func (s *Server) AppArn() string { return testAppArn }

func (s *Server) seed() {
	s.applications[testAppArn] = bonbon.Application{
		ApplicationArn: testAppArn,
		TenantId:       "tenant-bonbon",
		Status:         "ACTIVE",
		IdentitySource: &bonbon.IdentitySource{
			IdentityCenter: &bonbon.IdentityCenter{InstanceArn: "arn:aws:sso:::instance/ssoins-test"},
		},
		Tags: []bonbon.Tag{{Key: "env", Value: "test"}},
	}

	entries := []struct {
		role  string
		user  string
		group string
	}{
		{role: testRole1, user: UserId1},
		{role: testRole1, user: UserId2},
		{role: testRole1, group: GroupId1},
		{role: testRole2, user: UserId3},
		{role: testRole2, group: GroupId2},
	}
	for _, e := range entries {
		p := bonbon.Principal{IdentityCenter: &bonbon.IdentityCenterPrincipal{}}
		switch {
		case e.user != "":
			p.IdentityCenter.UserId = e.user
		case e.group != "":
			p.IdentityCenter.GroupId = e.group
		}
		s.addEntitlement(testAppArn, e.role, p)
	}
}

func (s *Server) addEntitlement(appArn, roleArn string, p bonbon.Principal) bonbon.EntitlementSummary {
	s.idSeq++
	id := fmt.Sprintf("ent-%04d", s.idSeq)
	sum := bonbon.EntitlementSummary{
		EntitlementId:  id,
		ApplicationArn: appArn,
		PrincipalRole: &bonbon.PrincipalRoleEntitlement{
			Principal: p,
			RoleArn:   roleArn,
		},
	}
	if _, ok := s.entitlements[appArn]; !ok {
		s.entitlements[appArn] = map[string]bonbon.EntitlementSummary{}
	}
	s.entitlements[appArn][id] = sum
	return sum
}

// Counts exposes counters for assertions: total applications + total entitlements.
func (s *Server) Counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entitlements := 0
	for _, m := range s.entitlements {
		entitlements += len(m)
	}
	return len(s.applications), entitlements
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/applications-list":
		s.handleListApplications(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/applications/"):
		s.handleGetApplication(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/tags/"):
		s.handleListTags(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/entitlements-list":
		s.handleListEntitlements(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/entitlements":
		s.handleCreateEntitlement(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/entitlements/"):
		s.handleDeleteEntitlement(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/entitlements/"):
		s.handleGetEntitlement(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var req bonbon.ListApplicationsRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	all := make([]bonbon.ApplicationSummary, 0, len(s.applications))
	for _, app := range s.applications {
		all = append(all, bonbon.ApplicationSummary{
			ApplicationArn: app.ApplicationArn,
			TenantId:       app.TenantId,
			Status:         app.Status,
		})
	}
	writeJSON(w, http.StatusOK, bonbon.ListApplicationsResponse{Applications: all})
}

func (s *Server) handleGetApplication(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	encoded := strings.TrimPrefix(r.URL.Path, "/applications/")
	arn, err := url.PathUnescape(encoded)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	app, ok := s.applications[arn]
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such application")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) handleListTags(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	encoded := strings.TrimPrefix(r.URL.Path, "/tags/")
	arn, err := url.PathUnescape(encoded)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if app, ok := s.applications[arn]; ok {
		writeJSON(w, http.StatusOK, bonbon.ListTagsForResourceResponse{Tags: app.Tags})
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such resource")
}

func (s *Server) handleListEntitlements(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var req bonbon.ListEntitlementsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.ApplicationArn == "" {
		writeError(w, http.StatusBadRequest, "ValidationException", "applicationArn is required")
		return
	}

	pool, ok := s.entitlements[req.ApplicationArn]
	if !ok {
		writeJSON(w, http.StatusOK, bonbon.ListEntitlementsResponse{})
		return
	}

	out := make([]bonbon.EntitlementSummary, 0, len(pool))
	for _, e := range pool {
		if req.Filter.PrincipalRole != nil {
			f := req.Filter.PrincipalRole
			if f.RoleArn != "" && f.RoleArn != e.PrincipalRole.RoleArn {
				continue
			}
			if f.Principal.IdentityCenter != nil && e.PrincipalRole.Principal.IdentityCenter != nil {
				if f.Principal.IdentityCenter.UserId != "" && f.Principal.IdentityCenter.UserId != e.PrincipalRole.Principal.IdentityCenter.UserId {
					continue
				}
				if f.Principal.IdentityCenter.GroupId != "" && f.Principal.IdentityCenter.GroupId != e.PrincipalRole.Principal.IdentityCenter.GroupId {
					continue
				}
			}
		}
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, bonbon.ListEntitlementsResponse{Entitlements: out})
}

func (s *Server) handleCreateEntitlement(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var req bonbon.CreateEntitlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.ApplicationArn == "" || req.PrincipalRole.RoleArn == "" {
		writeError(w, http.StatusBadRequest, "ValidationException", "applicationArn and principalRole.roleArn are required")
		return
	}

	pool, ok := s.entitlements[req.ApplicationArn]
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such application")
		return
	}

	for _, e := range pool {
		if e.PrincipalRole == nil {
			continue
		}
		if e.PrincipalRole.RoleArn != req.PrincipalRole.RoleArn {
			continue
		}
		if !principalEquals(e.PrincipalRole.Principal, req.PrincipalRole.Principal) {
			continue
		}
		writeError(w, http.StatusConflict, "AlreadyCreatedException", "entitlement already exists")
		return
	}

	sum := s.addEntitlement(req.ApplicationArn, req.PrincipalRole.RoleArn, req.PrincipalRole.Principal)
	writeJSON(w, http.StatusOK, bonbon.CreateEntitlementResponse{
		EntitlementId:  sum.EntitlementId,
		ApplicationArn: sum.ApplicationArn,
	})
}

func (s *Server) handleDeleteEntitlement(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	encoded := strings.TrimPrefix(r.URL.Path, "/entitlements/")
	id, err := url.PathUnescape(encoded)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	appArn := r.URL.Query().Get("applicationArn")
	if appArn == "" {
		writeError(w, http.StatusBadRequest, "ValidationException", "applicationArn is required")
		return
	}
	pool, ok := s.entitlements[appArn]
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such application")
		return
	}
	if _, ok := pool[id]; !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such entitlement")
		return
	}
	delete(pool, id)
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleGetEntitlement(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	encoded := strings.TrimPrefix(r.URL.Path, "/entitlements/")
	id, err := url.PathUnescape(encoded)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	appArn := r.URL.Query().Get("applicationArn")
	pool, ok := s.entitlements[appArn]
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such application")
		return
	}
	e, ok := pool[id]
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such entitlement")
		return
	}
	writeJSON(w, http.StatusOK, bonbon.GetEntitlementResponse{
		EntitlementId:  e.EntitlementId,
		ApplicationArn: e.ApplicationArn,
		PrincipalRole:  *e.PrincipalRole,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, errType, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Amzn-ErrorType", errType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"__type":  errType,
		"message": msg,
	})
}

func principalEquals(a, b bonbon.Principal) bool {
	if a.IdentityCenter == nil || b.IdentityCenter == nil {
		return a.IdentityCenter == b.IdentityCenter
	}
	return a.IdentityCenter.UserId == b.IdentityCenter.UserId &&
		a.IdentityCenter.GroupId == b.IdentityCenter.GroupId
}

// EntitlementCount returns total seeded entitlements for direct assertions.
func (s *Server) EntitlementCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, m := range s.entitlements {
		n += len(m)
	}
	return n
}

// ApplicationCount returns total seeded applications.
func (s *Server) ApplicationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.applications)
}

// ItoaIDs is a helper for round-trip tests over entitlement ids.
func ItoaIDs(ids []int) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.Itoa(id)
	}
	return out
}

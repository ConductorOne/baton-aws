package bonbontestserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/baton-aws/pkg/connector/bonbon/client"
)

type Server struct {
	URL          string
	listener     net.Listener
	server       *http.Server
	mu           sync.Mutex
	applications map[string]*application
	entitlements map[string]*entitlement
	nextID       int
}

type application struct {
	Arn         string
	TenantID    string
	Status      client.Status
	InstanceArn string
	Tags        map[string]string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type entitlement struct {
	ID             string
	ApplicationArn string
	Principal      client.Principal
	RoleArn        string
	Account        string
	CreatedAt      time.Time
}

func New(listenAddr ...string) (*Server, error) {
	addr := "127.0.0.1:0"
	if len(listenAddr) > 0 && listenAddr[0] != "" {
		addr = listenAddr[0]
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bonbon testserver: listen: %w", err)
	}
	s := &Server{
		listener:     listener,
		applications: map[string]*application{},
		entitlements: map[string]*entitlement{},
	}
	s.URL = "http://" + listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/applications", s.handleApplications)
	mux.HandleFunc("/applications/", s.handleApplicationItem)
	mux.HandleFunc("/applications-list", s.handleListApplications)
	mux.HandleFunc("/entitlements", s.handleEntitlements)
	mux.HandleFunc("/entitlements/", s.handleEntitlementItem)
	mux.HandleFunc("/entitlements-list", s.handleListEntitlements)
	mux.HandleFunc("/tags/", s.handleTags)
	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.server.Serve(listener) }()
	return s, nil
}

func (s *Server) Close() error { return s.server.Shutdown(context.Background()) }

func (s *Server) SeedApplication(arn, tenantID, instanceArn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.applications[arn] = &application{
		Arn:         arn,
		TenantID:    tenantID,
		Status:      client.StatusActive,
		InstanceArn: instanceArn,
		Tags:        map[string]string{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func (s *Server) SeedEntitlement(appArn string, principal client.Principal, roleArn, account string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	id := fmt.Sprintf("ent-%04d", s.nextID)
	s.entitlements[id] = &entitlement{
		ID:             id,
		ApplicationArn: appArn,
		Principal:      principal,
		RoleArn:        roleArn,
		Account:        account,
		CreatedAt:      time.Now().UTC(),
	}
	return id
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeAWSError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("X-Amzn-ErrorType", code)
	writeJSON(w, status, map[string]string{"message": msg})
}

func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSError(w, http.StatusMethodNotAllowed, string(client.ErrValidation), "method not allowed")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := client.ListApplicationsOutput{}
	for _, a := range s.applications {
		out.Applications = append(out.Applications, client.ApplicationSummary{
			ApplicationArn: a.Arn,
			TenantID:       a.TenantID,
			CreatedAt:      a.CreatedAt,
			UpdatedAt:      a.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleApplicationItem(w http.ResponseWriter, r *http.Request) {
	arn := strings.TrimPrefix(r.URL.Path, "/applications/")
	arn, _ = url.PathUnescape(arn)
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.applications[arn]
	if !ok {
		writeAWSError(w, http.StatusNotFound, string(client.ErrResourceNotFound), "application not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := client.GetApplicationOutput{
			IdentitySource: client.IdentitySourceDetails{
				IdentityCenter: &client.IdentityCenter{InstanceArn: a.InstanceArn},
			},
			Status:    a.Status,
			TenantID:  a.TenantID,
			CreatedAt: a.CreatedAt,
			UpdatedAt: a.UpdatedAt,
			Tags:      a.Tags,
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		delete(s.applications, arn)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeAWSError(w, http.StatusMethodNotAllowed, string(client.ErrValidation), "method not allowed")
	}
}

func (s *Server) handleApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSError(w, http.StatusMethodNotAllowed, string(client.ErrValidation), "method not allowed")
		return
	}
	writeAWSError(w, http.StatusNotImplemented, string(client.ErrValidation), "CreateApplication not implemented in testserver")
}

func (s *Server) handleListEntitlements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSError(w, http.StatusMethodNotAllowed, string(client.ErrValidation), "method not allowed")
		return
	}
	var in client.ListEntitlementsInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeAWSError(w, http.StatusBadRequest, string(client.ErrValidation), "decode body: "+err.Error())
		return
	}
	if in.ApplicationArn == "" {
		writeAWSError(w, http.StatusBadRequest, string(client.ErrValidation), "applicationArn required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := client.ListEntitlementsOutput{}
	for _, e := range s.entitlements {
		if e.ApplicationArn != in.ApplicationArn {
			continue
		}
		if in.Filter.PrincipalRole != nil && in.Filter.PrincipalRole.RoleArn != "" {
			if e.RoleArn != in.Filter.PrincipalRole.RoleArn {
				continue
			}
		}
		out.Entitlements = append(out.Entitlements, client.EntitlementsListMember{
			EntitlementID: e.ID,
			Entitlement: client.EntitlementSummary{
				PrincipalRole: &client.PrincipalRoleEntitlementSummary{
					Principal: e.Principal,
					RoleArn:   e.RoleArn,
					Account:   e.Account,
				},
			},
			CreatedAt: e.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleEntitlements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSError(w, http.StatusMethodNotAllowed, string(client.ErrValidation), "method not allowed")
		return
	}
	var in client.CreateEntitlementInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeAWSError(w, http.StatusBadRequest, string(client.ErrValidation), "decode body: "+err.Error())
		return
	}
	if in.Entitlement.PrincipalRole == nil {
		writeAWSError(w, http.StatusBadRequest, string(client.ErrValidation), "principalRole required")
		return
	}
	id := s.SeedEntitlement(
		in.ApplicationArn,
		in.Entitlement.PrincipalRole.Principal,
		in.Entitlement.PrincipalRole.RoleArn,
		accountFromRoleArn(in.Entitlement.PrincipalRole.RoleArn),
	)
	writeJSON(w, http.StatusOK, client.CreateEntitlementOutput{EntitlementID: id})
}

func (s *Server) handleEntitlementItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/entitlements/")
	id, _ = url.PathUnescape(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entitlements[id]
	if !ok {
		writeAWSError(w, http.StatusNotFound, string(client.ErrResourceNotFound), "entitlement not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, client.GetEntitlementOutput{
			ApplicationArn: e.ApplicationArn,
			EntitlementID:  e.ID,
			Entitlement: client.EntitlementDetails{
				PrincipalRole: &client.PrincipalRoleEntitlementDetails{
					Principal: e.Principal,
					RoleArn:   e.RoleArn,
					Account:   e.Account,
				},
			},
			CreatedAt: e.CreatedAt,
		})
	case http.MethodDelete:
		delete(s.entitlements, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeAWSError(w, http.StatusMethodNotAllowed, string(client.ErrValidation), "method not allowed")
	}
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, client.ListTagsForResourceOutput{Tags: map[string]string{}})
}

func accountFromRoleArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

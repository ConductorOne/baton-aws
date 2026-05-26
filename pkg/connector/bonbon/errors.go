package bonbon

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// APIError is the canonical structured error returned by the AWS
// Account Access Manager service. Callers extract Type with errors.As to
// branch on AlreadyCreatedException / ResourceNotFoundException without
// relying on HTTP status alone — the service-2.json declares the shapes
// but does not pin status codes for every modeled error.
type APIError struct {
	Type       string
	Message    string
	StatusCode int
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("bonbon: %s: %s", e.Type, e.Message)
	}
	return fmt.Sprintf("bonbon: %s (status %d)", e.Type, e.StatusCode)
}

func parseAPIError(resp *http.Response, body []byte) *APIError {
	p := decodeError(body)
	t := p.Type
	if t == "" {
		t = resp.Header.Get("X-Amzn-ErrorType")
	}
	if idx := strings.IndexByte(t, ':'); idx >= 0 {
		t = t[:idx]
	}
	if idx := strings.LastIndexByte(t, '#'); idx >= 0 {
		t = t[idx+1:]
	}
	return &APIError{Type: t, Message: p.Message, StatusCode: resp.StatusCode}
}

func isType(err error, t string) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Type == t
}

func IsAlreadyCreated(err error) bool   { return isType(err, "AlreadyCreatedException") }
func IsResourceNotFound(err error) bool { return isType(err, "ResourceNotFoundException") }
func IsValidation(err error) bool       { return isType(err, "ValidationException") }
func IsAccessDenied(err error) bool     { return isType(err, "AccessDeniedException") }
func IsConflict(err error) bool         { return isType(err, "ConflictException") }
func IsThrottling(err error) bool       { return isType(err, "ThrottlingException") }
func IsInternalServer(err error) bool   { return isType(err, "InternalServerException") }

// WrapForRetry maps transient service errors to gRPC Unavailable so the
// baton-sdk sync engine retries them. Permanent errors pass through.
func WrapForRetry(err error) error {
	if err == nil {
		return nil
	}
	if IsThrottling(err) || IsInternalServer(err) {
		return status.Error(codes.Unavailable, err.Error())
	}
	return err
}

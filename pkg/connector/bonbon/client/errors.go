package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type ErrorCode string

const (
	ErrAccessDenied        ErrorCode = "AccessDeniedException"
	ErrAlreadyCreated      ErrorCode = "AlreadyCreatedException"
	ErrConflict            ErrorCode = "ConflictException"
	ErrInternalServer      ErrorCode = "InternalServerException"
	ErrResourceNotFound    ErrorCode = "ResourceNotFoundException"
	ErrThrottling          ErrorCode = "ThrottlingException"
	ErrValidation          ErrorCode = "ValidationException"
)

type APIError struct {
	StatusCode int
	Code       ErrorCode
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("bonbon: %s (status %d)", e.Code, e.StatusCode)
	}
	return fmt.Sprintf("bonbon: %s (status %d): %s", e.Code, e.StatusCode, e.Message)
}

func IsCode(err error, code ErrorCode) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code == code
	}
	return false
}

func parseError(status int, header http.Header, body []byte) error {
	code := ErrorCode(extractErrorType(header, body))
	var payload struct {
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &payload)
	}
	msg := payload.Message
	if msg == "" {
		msg = payload.Msg
	}
	if code == "" {
		code = ErrorCode(http.StatusText(status))
	}
	return &APIError{StatusCode: status, Code: code, Message: msg}
}

func extractErrorType(header http.Header, body []byte) string {
	if h := header.Get("X-Amzn-ErrorType"); h != "" {
		return trimErrorType(h)
	}
	var typed struct {
		Type     string `json:"__type"`
		TypeAlt  string `json:"code"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &typed)
	}
	if typed.Type != "" {
		return trimErrorType(typed.Type)
	}
	return typed.TypeAlt
}

func trimErrorType(raw string) string {
	if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, "#"); i >= 0 {
		raw = raw[i+1:]
	}
	return strings.TrimSpace(raw)
}

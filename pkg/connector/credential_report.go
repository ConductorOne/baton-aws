package connector

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	consoleAccessEntitlement = "console_access"

	credentialReportMaxWait  = 2 * time.Minute
	credentialReportPollWait = 2 * time.Second
)

type credentialReportEntry struct {
	User                string
	PasswordEnabled     string
	PasswordLastUsed    string
	PasswordLastChanged string
}

func (e *credentialReportEntry) IsPasswordEnabled() bool {
	return strings.EqualFold(e.PasswordEnabled, "true")
}

func (e *credentialReportEntry) ParsePasswordLastUsed() *time.Time {
	return parseCredentialReportTime(e.PasswordLastUsed)
}

func (e *credentialReportEntry) ParsePasswordLastChanged() *time.Time {
	return parseCredentialReportTime(e.PasswordLastChanged)
}

func parseCredentialReportTime(s string) *time.Time {
	if s == "" || s == "N/A" || s == "not_supported" || s == "no_information" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// fetchCredentialReport generates and retrieves the IAM credential report,
// returning a map keyed by IAM username.
func fetchCredentialReport(ctx context.Context, iamClient *iam.Client) (map[string]*credentialReportEntry, error) {
	if err := generateCredentialReport(ctx, iamClient); err != nil {
		return nil, err
	}

	content, err := getCredentialReport(ctx, iamClient)
	if err != nil {
		return nil, err
	}

	return parseCredentialReportCSV(content)
}

func generateCredentialReport(ctx context.Context, iamClient *iam.Client) error {
	deadline := time.Now().Add(credentialReportMaxWait)

	for {
		resp, err := iamClient.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return fmt.Errorf("baton-aws: iam.GenerateCredentialReport failed: %w", err)
		}

		if resp.State == iamTypes.ReportStateTypeComplete {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("baton-aws: credential report generation timed out after %v", credentialReportMaxWait)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(credentialReportPollWait):
		}
	}
}

func getCredentialReport(ctx context.Context, iamClient *iam.Client) ([]byte, error) {
	resp, err := iamClient.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		var notReady *iamTypes.CredentialReportNotReadyException
		if errors.As(err, &notReady) {
			return nil, fmt.Errorf("baton-aws: credential report not ready: %w", err)
		}
		var notPresent *iamTypes.CredentialReportNotPresentException
		if errors.As(err, &notPresent) {
			return nil, fmt.Errorf("baton-aws: credential report not present: %w", err)
		}
		return nil, fmt.Errorf("baton-aws: iam.GetCredentialReport failed: %w", err)
	}

	return resp.Content, nil
}

func parseCredentialReportCSV(content []byte) (map[string]*credentialReportEntry, error) {
	reader := csv.NewReader(bytes.NewReader(content))

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("baton-aws: failed to read credential report header: %w", err)
	}

	colIndex := make(map[string]int, len(header))
	for i, col := range header {
		colIndex[col] = i
	}

	requiredCols := []string{"user", "password_enabled"}
	for _, col := range requiredCols {
		if _, ok := colIndex[col]; !ok {
			return nil, fmt.Errorf("baton-aws: credential report missing required column: %s", col)
		}
	}

	result := make(map[string]*credentialReportEntry)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("baton-aws: failed to read credential report row: %w", err)
		}

		entry := &credentialReportEntry{}

		if idx, ok := colIndex["user"]; ok && idx < len(record) {
			entry.User = record[idx]
		}
		if idx, ok := colIndex["password_enabled"]; ok && idx < len(record) {
			entry.PasswordEnabled = record[idx]
		}
		if idx, ok := colIndex["password_last_used"]; ok && idx < len(record) {
			entry.PasswordLastUsed = record[idx]
		}
		if idx, ok := colIndex["password_last_changed"]; ok && idx < len(record) {
			entry.PasswordLastChanged = record[idx]
		}

		if entry.User == "<root_account>" {
			continue
		}

		result[entry.User] = entry
	}

	return result, nil
}

// fetchCredentialReportBestEffort fetches the credential report, logging and
// returning nil on failure so callers can degrade gracefully.
func fetchCredentialReportBestEffort(ctx context.Context, iamClient *iam.Client) map[string]*credentialReportEntry {
	l := ctxzap.Extract(ctx)
	report, err := fetchCredentialReport(ctx, iamClient)
	if err != nil {
		l.Warn("baton-aws: failed to fetch credential report, console access data will be unavailable", zap.Error(err))
		return nil
	}
	return report
}
